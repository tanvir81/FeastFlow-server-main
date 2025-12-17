const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const app = express();
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 3000;
// Stripe setup
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
// Firebase Admin setup
const admin = require("firebase-admin");
admin.initializeApp({
  credential: admin.credential.cert(require("./firebase-service-account.json")),
});
// Middleware
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
app.use(cookieParser());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@mydb81.7dbidnl.mongodb.net/?appName=MyDB81`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// JWT + Roles Middleware

const verifyJWT = async (req, res, next) => {
  try {
    const cookieToken = req.cookies?.token;
    if (cookieToken) {
      try {
        const decoded = jwt.verify(cookieToken, process.env.JWT_SECRET);

        const db = client.db("feastflow_db");
        const user = await db
          .collection("users")
          .findOne({ email: decoded.email });
        if (!user) {
          return res
            .status(401)
            .json({ error: "Unauthorized - user not found" });
        }

        // Override role with DB value
        req.user = { ...decoded, role: user.role };
        return next();
      } catch (err) {
        return res
          .status(401)
          .json({ error: "Unauthorized - invalid app JWT cookie" });
      }
    }

    // Firebase ID token via Authorization header
    const authHeader = req.headers.authorization;
    const bearerToken = authHeader?.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : null;
    if (!bearerToken) {
      return res.status(401).json({ error: "Unauthorized - no token" });
    }

    const decodedFirebase = await admin.auth().verifyIdToken(bearerToken);

    //  Always check MongoDB for latest role
    const db = client.db("feastflow_db");
    const user = await db
      .collection("users")
      .findOne({ email: decodedFirebase.email });
    if (!user) {
      return res.status(401).json({ error: "Unauthorized - user not found" });
    }

    req.user = {
      uid: decodedFirebase.uid,
      email: decodedFirebase.email,
      role: user.role || "user",
    };
    return next();
  } catch (err) {
    return res
      .status(401)
      .json({ error: "Unauthorized - token verification failed" });
  }
};
// Role guards
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admins only" });
  }
  next();
};

const verifyChef = (req, res, next) => {
  if (req.user.role !== "chef") {
    return res.status(403).json({ error: "Chefs only" });
  }
  next();
};

// DB connection

async function run() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("Connected to MongoDB!");
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err);
  }
}
run().catch(console.dir);

// Root

app.get("/", (req, res) => {
  res.send("feastflow is running!!!");
});

// Auth routes (Firebase verify + JWT issue/clear)

app.post("/login", async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: "ID token required" });

    // Verify Firebase ID token
    const decoded = await admin.auth().verifyIdToken(idToken);

    const uid = decoded.uid;
    const email = decoded.email;
    const role = decoded.role || "user";

    // check MongoDB for extra user info
    const db = client.db("feastflow_db");
    const user = await db.collection("users").findOne({ email });

    // Issue JWT for cookie/session
    const token = jwt.sign(
      { uid, email, role, dbId: user?._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    const isProduction = process.env.NODE_ENV === "production";
    res.cookie("token", token, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
    });

    res.json({ success: true, message: "Logged in successfully", role });
  } catch (error) {
    console.error("Login failed:", error);
    res.status(401).json({ error: "Unauthorized", details: error?.message });
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true, message: "Logged out successfully" });
});

// User Registration (Firebase + MongoDB + JWT)

app.post("/register", async (req, res) => {
  try {
    const { idToken, name, address, profileImage } = req.body;
    if (!idToken) return res.status(400).json({ error: "ID token required" });

    // Verify Firebase ID token
    const decoded = await admin.auth().verifyIdToken(idToken);
    const uid = decoded.uid;
    const email = decoded.email;

    const db = client.db("feastflow_db");
    const usersCollection = db.collection("users");

    // Check if user already exists in MongoDB
    const user = await usersCollection.findOne({ email });
    let dbUser = user;

    if (!dbUser) {
      // Insert new user with extra fields
      const result = await usersCollection.insertOne({
        uid,
        email,
        name,
        address,
        profileImage,
        status: "active",
        createdAt: new Date(),
      });
      dbUser = await usersCollection.findOne({ _id: result.insertedId });
    }

    // Issue JWT
    const token = jwt.sign(
      { uid, email, role: "user", dbId: dbUser._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    const isProduction = process.env.NODE_ENV === "production";
    res.cookie("token", token, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
    });

    res.json({
      success: true,
      message: "Registered and logged in successfully",
      user: dbUser,
    });
  } catch (error) {
    console.error("Registration failed:", error);
    res
      .status(500)
      .json({ error: "Registration failed", details: error?.message });
  }
});
app.get("/me", verifyJWT, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const user = await db
      .collection("users")
      .findOne({ email: req.user.email });

    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ user });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// All Meals

//  get meals
app.get("/meals", async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;
    const db = client.db("feastflow_db");
    const meals = await db.collection("meals").find({}).limit(limit).toArray();
    res.send(meals);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch meals", error });
  }
});

// code Get meals for logged-in chef
app.get("/my-meals", verifyJWT, verifyChef, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const meals = await db
      .collection("meals")
      .find({ chefId: req.user.uid })
      .toArray();

    res.send(meals);
  } catch (error) {
    console.error("Chef meals fetch failed:", error);
    res
      .status(500)
      .send({ message: "Failed to fetch chef meals", error: error.message });
  }
});

// Get single meal by ID part
app.get("/meals/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const db = client.db("feastflow_db");
    const meal = await db
      .collection("meals")
      .findOne({ _id: new ObjectId(id) });

    if (!meal) {
      return res.status(404).send({ message: "Meal not found" });
    }

    res.send(meal);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch meal", error });
  }
});

app.post("/meals", verifyJWT, verifyChef, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const {
      foodName,
      chefName,
      foodImage,
      price,
      rating = 0,
      ingredients,
      estimatedDeliveryTime,
      chefExperience,
      userEmail,
    } = req.body;

    if (
      !foodName ||
      !chefName ||
      !foodImage ||
      price == null ||
      !ingredients ||
      !estimatedDeliveryTime ||
      !chefExperience
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const doc = {
      foodName,
      chefName,
      foodImage,
      price: Number(price),
      rating: Number(rating) || 0,
      ingredients: Array.isArray(ingredients)
        ? ingredients
        : String(ingredients)
            .split(",")
            .map((i) => i.trim())
            .filter(Boolean),
      estimatedDeliveryTime,
      chefExperience,
      chefId: req.user.uid,
      userEmail: userEmail || req.user.email,
      chefEmail: req.user.email,
      createdAt: new Date(),
    };

    const result = await db.collection("meals").insertOne(doc);
    res.json({ success: true, mealId: result.insertedId });
  } catch (error) {
    res
      .status(500)
      .send({ message: "Failed to insert meal", error: error.message });
  }
});

// Update a meal section
app.patch("/meals/:id", verifyJWT, verifyChef, async (req, res) => {
  try {
    const id = req.params.id;
    const db = client.db("feastflow_db");
    const { _id, chefId, userEmail, chefEmail, createdAt, ...updateFields } =
      req.body;

    const allowed = [
      "foodName",
      "chefName",
      "price",
      "rating",
      "ingredients",
      "estimatedDeliveryTime",
      "chefExperience",
      "foodImage",
    ];
    const safeUpdate = Object.fromEntries(
      Object.entries(updateFields).filter(([k]) => allowed.includes(k))
    );
    if (safeUpdate.ingredients && !Array.isArray(safeUpdate.ingredients)) {
      safeUpdate.ingredients = String(safeUpdate.ingredients)
        .split(",")
        .map((i) => i.trim())
        .filter(Boolean);
    }

    const result = await db
      .collection("meals")
      .updateOne(
        { _id: new ObjectId(id), chefId: req.user.uid },
        { $set: safeUpdate }
      );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: "Meal not found or not updated" });
    }

    res.json({ success: true, modifiedCount: result.modifiedCount });
  } catch (error) {
    res
      .status(500)
      .send({ message: "Failed to update meal", error: error.message });
  }
});

// Delete a meal
app.delete("/meals/:id", verifyJWT, verifyChef, async (req, res) => {
  try {
    const id = req.params.id;
    const db = client.db("feastflow_db");
    const result = await db
      .collection("meals")
      .deleteOne({ _id: new ObjectId(id), chefId: req.user.uid });
    res.json({ success: true, deletedCount: result.deletedCount });
  } catch (error) {
    res.status(500).send({ message: "Failed to delete meal", error });
  }
});

// All Review
app.get("/reviews", async (req, res) => {
  try {
    const { foodId, limit } = req.query;
    const db = client.db("feastflow_db");

    const query = foodId ? { foodId } : {};
    let cursor = db.collection("reviews").find(query).sort({ date: -1 });

    if (limit) {
      cursor = cursor.limit(parseInt(limit));
    }

    const reviews = await cursor.toArray();
    res.send(reviews);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch reviews", error });
  }
});

app.post("/reviews", verifyJWT, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const body = req.body;
    const doc = { ...body, userEmail: req.user.email, date: new Date() };
    const result = await db.collection("reviews").insertOne(doc);
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to insert review", error });
  }
});
// my review
// Get reviews for logged-in user
app.get("/my-reviews", verifyJWT, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const reviews = await db
      .collection("reviews")
      .find({ userEmail: req.user.email })
      .toArray();
    res.send(reviews);
  } catch (error) {
    res
      .status(500)
      .send({ message: "Failed to fetch reviews", error: error.message });
  }
});
// Add a new review (logged-in user)
app.post("/reviews", verifyJWT, async (req, res) => {
  try {
    const { foodId, mealName, rating, comment } = req.body;
    const db = client.db("feastflow_db");

    const review = {
      foodId,
      mealName,
      reviewerName: req.user.name,
      reviewerImage: req.user.image,
      rating: Number(rating),
      comment,
      userEmail: req.user.email,
      date: new Date(),
    };

    const result = await db.collection("reviews").insertOne(review);
    res.json({ success: true, reviewId: result.insertedId });
  } catch (error) {
    res
      .status(500)
      .send({ message: "Failed to add review", error: error.message });
  }
});

// Delete a review
app.delete("/reviews/:id", verifyJWT, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const result = await db.collection("reviews").deleteOne({
      _id: new ObjectId(req.params.id),
      userEmail: req.user.email,
    });
    res.json({ success: result.deletedCount > 0 });
  } catch (error) {
    res
      .status(500)
      .send({ message: "Failed to delete review", error: error.message });
  }
});

// Update a review
app.patch("/reviews/:id", verifyJWT, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const db = client.db("feastflow_db");
    const result = await db
      .collection("reviews")
      .updateOne(
        { _id: new ObjectId(req.params.id), userEmail: req.user.email },
        { $set: { rating, comment, date: new Date() } }
      );
    res.json({ success: result.modifiedCount > 0 });
  } catch (error) {
    res
      .status(500)
      .send({ message: "Failed to update review", error: error.message });
  }
});
// Add a meal to favorites
app.post("/favorites", verifyJWT, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const { userEmail, mealId, mealName, chefId, chefName, price, addedTime } =
      req.body;

    // Prevent duplicates
    const existing = await db
      .collection("favorites")
      .findOne({ userEmail, mealId });
    if (existing) {
      return res.status(400).send({ message: "Already in favorites" });
    }

    const favorite = {
      userEmail,
      mealId,
      mealName,
      chefId,
      chefName,
      price,
      addedTime,
    };
    const result = await db.collection("favorites").insertOne(favorite);

    res.json({ success: true, favoriteId: result.insertedId });
  } catch (error) {
    res
      .status(500)
      .send({ message: "Failed to add favorite", error: error.message });
  }
});

// Get favorites for logged-in user
app.get("/favorites", verifyJWT, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const favorites = await db
      .collection("favorites")
      .find({ userEmail: req.user.email })
      .toArray();
    res.send(favorites);
  } catch (error) {
    res
      .status(500)
      .send({ message: "Failed to fetch favorites", error: error.message });
  }
});

// Remove from favorites
app.delete("/favorites/:id", verifyJWT, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const result = await db.collection("favorites").deleteOne({
      _id: new ObjectId(req.params.id),
      userEmail: req.user.email,
    });
    res.json({ success: result.deletedCount > 0 });
  } catch (error) {
    res
      .status(500)
      .send({ message: "Failed to delete favorite", error: error.message });
  }
});

// Role Requests
// Normal user creates a role request
app.post("/requests", verifyJWT, async (req, res) => {
  try {
    const { email, requestedRole } = req.body;
    if (!email || !requestedRole) {
      return res
        .status(400)
        .json({ error: "Email and requestedRole required" });
    }

    const db = client.db("feastflow_db");

    // Prevent duplicate pending requests for same user/role
    const existing = await db.collection("roleRequests").findOne({
      email,
      requestedRole,
      status: "pending",
    });
    if (existing) {
      return res.status(400).json({ error: "Request already pending" });
    }

    const result = await db.collection("roleRequests").insertOne({
      email,
      requestedRole,
      status: "pending",
      createdAt: new Date(),
    });

    res.json({ success: true, requestId: result.insertedId });
  } catch (error) {
    res.status(500).send({ message: "Failed to create request", error });
  }
});

// Admin fetches all requests
app.get("/requests", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const requests = await db
      .collection("roleRequests")
      .aggregate([
        {
          $lookup: {
            from: "users",
            localField: "email",
            foreignField: "email",
            as: "user",
          },
        },
        {
          $unwind: {
            path: "$user",
            preserveNullAndEmptyArrays: true,
          },
        },
        {
          $project: {
            email: 1,
            requestedRole: 1,
            status: 1,
            createdAt: 1,
            userName: "$user.name",
            userImage: "$user.profileImage",
          },
        },
      ])
      .toArray();

    res.send(requests);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch requests", error });
  }
});

// Admin approves/rejects a role request

app.patch("/requests/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const id = req.params.id;

    const db = client.db("feastflow_db");
    const request = await db
      .collection("roleRequests")
      .findOne({ _id: new ObjectId(id) });

    if (!request) {
      return res.status(404).json({ error: "Request not found" });
    }

    //  Update request status
    await db
      .collection("roleRequests")
      .updateOne({ _id: new ObjectId(id) }, { $set: { status } });

    if (status === "approved") {
      // Update user role in MongoDB
      await db
        .collection("users")
        .updateOne(
          { email: request.email },
          { $set: { role: request.requestedRole } }
        );

      //  Update Firebase custom claims
      const record = await admin.auth().getUserByEmail(request.email);
      await admin.auth().setCustomUserClaims(record.uid, {
        role: request.requestedRole,
      });
      await admin.auth().revokeRefreshTokens(record.uid);
    }

    res.json({ success: true, message: `Request ${status}` });
  } catch (error) {
    console.error("Role request update failed:", error);
    res.status(500).send({ message: "Failed to update request", error });
  }
});

// Promote a user to admin (admin-only route)

app.patch("/users/:email/promote", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const { newRole } = req.body;
    const email = req.params.email;

    const db = client.db("feastflow_db");
    const user = await db.collection("users").findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    // Update MongoDB role
    await db
      .collection("users")
      .updateOne({ email }, { $set: { role: newRole } });

    // Update Firebase custom claims
    const record = await admin.auth().getUserByEmail(email);
    await admin.auth().setCustomUserClaims(record.uid, { role: newRole });
    await admin.auth().revokeRefreshTokens(record.uid);

    res.json({ success: true, message: `${email} promoted to ${newRole}` });
  } catch (err) {
    console.error("Promotion failed:", err);
    res
      .status(500)
      .json({ error: "Failed to promote user", details: err.message });
  }
});

// Users
app.post("/users", async (req, res) => {
  try {
    const { uid, email, role, name, profileImage } = req.body;

    if (!uid || !email || !role) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const db = client.db("feastflow_db");

    // Prevent duplicate users by UID
    const existing = await db.collection("users").findOne({ uid });
    if (existing) {
      return res.json({ success: true, message: "User already exists" });
    }

    const result = await db.collection("users").insertOne({
      uid,
      email,
      name: name || "",
      profileImage: profileImage || "",
      role: role || "user",
      createdAt: new Date(),
    });

    res.json({ success: true, userId: result.insertedId });
  } catch (error) {
    console.error("User creation failed:", error);
    res
      .status(500)
      .send({ message: "Failed to create user", error: error.message });
  }
});

// Admin fetches all users
app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const users = await db.collection("users").find({}).toArray();
    res.send(users);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch users", error });
  }
});

// Admin updates user role or status
app.patch("/users/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const { role, status } = req.body;
    const id = req.params.id;
    const db = client.db("feastflow_db");

    const updateDoc = {};
    if (role) updateDoc.role = role;
    if (status) updateDoc.status = status;

    if (Object.keys(updateDoc).length === 0) {
      return res.status(400).json({ error: "Nothing to update" });
    }

    const result = await db
      .collection("users")
      .updateOne({ _id: new ObjectId(id) }, { $set: updateDoc });

    res.json({ success: true, modifiedCount: result.modifiedCount });
  } catch (error) {
    res.status(500).send({ message: "Failed to update user", error });
  }
});

// Statistics (Admin)

app.get("/statistics", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const db = client.db("feastflow_db");

    const totalUsers = await db.collection("users").countDocuments();
    const totalMeals = await db.collection("meals").countDocuments();
    const totalReviews = await db.collection("reviews").countDocuments();
    const ordersPending = await db
      .collection("orders")
      .countDocuments({ orderStatus: "pending" });
    const ordersDelivered = await db
      .collection("orders")
      .countDocuments({ orderStatus: "delivered" });
    const totalPayments = await db
      .collection("payments")
      .aggregate([{ $group: { _id: null, sum: { $sum: "$amount" } } }])
      .toArray();

    res.json({
      totalUsers,
      totalMeals,
      totalReviews,
      ordersPending,
      ordersDelivered,
      totalPayments: totalPayments[0]?.sum || 0,
    });
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch statistics", error });
  }
});

// Orders

// Create order
app.post("/orders", verifyJWT, async (req, res) => {
  try {
    const { foodId, mealName, price, quantity, chefId, userAddress } = req.body;

    if (!foodId || !mealName || !price || !quantity || !userAddress) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const db = client.db("feastflow_db");
    const result = await db.collection("orders").insertOne({
      foodId,
      mealName,
      price,
      quantity,
      chefId,
      userEmail: req.user.email,
      userUid: req.user.uid,
      userAddress,
      paymentStatus: "Pending",
      orderStatus: "pending",
      orderTime: new Date(),
    });

    res.json({ success: true, orderId: result.insertedId });
  } catch (error) {
    console.error("Order creation failed:", error);
    res.status(500).send({ message: "Failed to create order", error });
  }
});

// Get orders for logged-in user
app.get("/orders", verifyJWT, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const orders = await db
      .collection("orders")
      .aggregate([
        { $match: { userUid: req.user.uid } },
        {
          $lookup: {
            from: "users",
            localField: "chefId",
            foreignField: "uid",
            as: "chefInfo",
          },
        },
        {
          $unwind: {
            path: "$chefInfo",
            preserveNullAndEmptyArrays: true,
          },
        },
        {
          $addFields: {
            chefName: {
              $ifNull: ["$chefInfo.name", "Unknown Chef"],
            },
            chefUid: {
              $ifNull: ["$chefInfo.uid", null],
            },
          },
        },
        {
          $project: {
            chefInfo: 0,
          },
        },
      ])
      .toArray();

    // Debug logging
    console.log("Orders fetched:", orders.length);
    if (orders.length > 0) {
      console.log("Sample order:", {
        chefId: orders[0].chefId,
        chefName: orders[0].chefName,
        chefUid: orders[0].chefUid,
      });
    }

    res.send(orders);
  } catch (error) {
    console.error("Order fetch failed:", error);
    res.status(500).send({ message: "Failed to fetch orders", error });
  }
});
// Get orders for logged-in chef
app.get("/chef-orders", verifyJWT, verifyChef, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const orders = await db
      .collection("orders")
      .find({ chefId: req.user.uid })
      .toArray();
    res.send(orders);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch chef orders", error });
  }
});

// Orders
// Create order
app.post("/orders", verifyJWT, async (req, res) => {
  try {
    const { foodId, mealName, price, quantity, chefId, userAddress } = req.body;

    if (!foodId || !mealName || !price || !quantity || !userAddress) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const db = client.db("feastflow_db");
    const result = await db.collection("orders").insertOne({
      foodId,
      mealName,
      price,
      quantity,
      chefId,
      userEmail: req.user.email,
      userUid: req.user.uid,
      userAddress,
      paymentStatus: "Pending",
      orderStatus: "pending",
      orderTime: new Date(),
    });

    res.json({ success: true, orderId: result.insertedId });
  } catch (error) {
    console.error("Order creation failed:", error);
    res.status(500).send({ message: "Failed to create order", error });
  }
});

// Get orders for logged-in user
app.get("/orders", verifyJWT, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const orders = await db
      .collection("orders")
      .find({ userUid: req.user.uid })
      .toArray();

    res.send(orders);
  } catch (error) {
    console.error("Order fetch failed:", error);
    res.status(500).send({ message: "Failed to fetch orders", error });
  }
});
// Get orders for logged-in chef
app.get("/chef-orders", verifyJWT, verifyChef, async (req, res) => {
  try {
    const db = client.db("feastflow_db");
    const orders = await db
      .collection("orders")
      .find({ chefId: req.user.uid })
      .toArray();
    res.send(orders);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch chef orders", error });
  }
});

// Update order status (Cancel, Accept, Deliver)
app.patch("/orders/:id", verifyJWT, verifyChef, async (req, res) => {
  try {
    const id = req.params.id;
    const { status } = req.body;
    const db = client.db("feastflow_db");

    const result = await db
      .collection("orders")
      .updateOne(
        { _id: new ObjectId(id), chefId: req.user.uid },
        { $set: { orderStatus: status } }
      );

    res.json({ success: true, modifiedCount: result.modifiedCount });
  } catch (error) {
    res.status(500).send({ message: "Failed to update order status", error });
  }
});
// Accept order
app.patch("/orders/:id/accept", verifyJWT, verifyChef, async (req, res) => {
  try {
    const id = req.params.id;
    const db = client.db("feastflow_db");
    const result = await db
      .collection("orders")
      .updateOne(
        { _id: new ObjectId(id), chefId: req.user.uid },
        { $set: { orderStatus: "accepted" } }
      );
    res.json({ success: true, modifiedCount: result.modifiedCount });
  } catch (error) {
    res.status(500).send({ message: "Failed to accept order", error });
  }
});
// Deliver order  if paid
app.patch("/orders/:id/deliver", verifyJWT, verifyChef, async (req, res) => {
  try {
    const id = req.params.id;
    const db = client.db("feastflow_db");

    const order = await db.collection("orders").findOne({
      _id: new ObjectId(id),
      chefId: req.user.uid,
    });

    if (!order) {
      return res
        .status(404)
        .json({ success: false, message: "Order not found" });
    }

    if (order.paymentStatus?.toLowerCase() !== "paid") {
      return res.status(400).json({
        success: false,
        message: "Order must be paid before delivery",
      });
    }

    const result = await db
      .collection("orders")
      .updateOne(
        { _id: new ObjectId(id), chefId: req.user.uid },
        { $set: { orderStatus: "delivered" } }
      );

    res.json({ success: true, modifiedCount: result.modifiedCount });
  } catch (error) {
    res.status(500).send({ message: "Failed to deliver order", error });
  }
});

// Stripe Payment Integration

app.post("/create-checkout-session", verifyJWT, async (req, res) => {
  try {
    const { orderId, mealName, price } = req.body;
    if (!orderId || !mealName || !price) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const session = await stripe.checkout.sessions.create({
      line_items: [
        {
          price_data: {
            currency: "usd",
            unit_amount: price * 100,
            product_data: { name: mealName },
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      metadata: { orderId },
      customer_email: req.user.email,
      success_url: `${process.env.SITE_DOMAIN}/payment-success?orderId=${orderId}&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.SITE_DOMAIN}/dashboard/orders?canceled=true`,
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error("Failed to create checkout session:", error);
    res
      .status(500)
      .send({ message: "Failed to create checkout session", error });
  }
});

// Handle payment success
app.patch("/payment-success", async (req, res) => {
  try {
    const sessionId = req.query.session_id;
    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (!session) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid session" });
    }

    const orderId = session.metadata.orderId;
    const transactionId = session.payment_intent;

    if (session.payment_status === "paid") {
      const db = client.db("feastflow_db");
      const paymentsCollection = db.collection("payments");
      const ordersCollection = db.collection("orders");

      //  only insert if not exists
      const result = await paymentsCollection.updateOne(
        { transactionId },
        {
          $setOnInsert: {
            userEmail: session.customer_email,
            amount: session.amount_total / 100,
            currency: session.currency,
            orderId,
            transactionId,
            paymentStatus: session.payment_status,
            paidAt: new Date(),
          },
        },
        { upsert: true }
      );

      // update order status
      await ordersCollection.updateOne(
        { _id: new ObjectId(orderId) },
        { $set: { paymentStatus: "paid", orderStatus: "accepted" } }
      );

      // Decide response message new
      const message =
        result.upsertedCount === 0
          ? "Payment already recorded"
          : "Payment recorded successfully";

      return res.json({
        success: true,
        message,
        orderId,
        transactionId,
      });
    }

    res.json({ success: false });
  } catch (error) {
    console.error("Failed to process payment success:", error);
    res.status(500).send({
      success: false,
      message: "Failed to process payment success",
      error,
    });
  }
});

// Listen
app.listen(port, () => {
  console.log(` feastflow server running on port ${port}`);
});
