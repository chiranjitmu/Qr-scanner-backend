const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const auth = require("./middleware/authenticate.js");

const app = express();
app.use(cors());
const port = 8000;
app.use(bodyParser.json());
dotenv.config();

const uri = process.env.MONGODB_URI;

mongoose.connect(uri);

const db = mongoose.connection;

db.on("error", console.error.bind(console, "MongoDB connection error:"));

// Define Mongoose schema
const userSchema = new mongoose.Schema({
  fullname: String,
  email: { type: String, unique: true },
  password_hash: String,
});

const User = mongoose.model("User", userSchema);

const qrScannerSchema = new mongoose.Schema({
  content: String,
  date: Date,
  username: String,
});

const QRScanner = mongoose.model("QRScanner", qrScannerSchema);

app.get("/", async (req, res) => {
  res.send("uptime")
})

// login
app.get("/api/v1/login", async (req, res) => {
  try {
    const { email, password } = req.query;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "Invalid email" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid password" });
    }

    const token = jwt.sign({ email }, process.env.SECRET_KEY, {
      expiresIn: "7h",
    });

    res.status(200).json({ message: "Login successful", token, email });
  } catch (error) {
    res.status(500).json({ error: "Something went wrong!" });
  }
});

// register
app.post("/api/v1/register", async (req, res) => {
  try {
    const { fullname, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      fullname,
      email,
      password_hash: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "Something went wrong!" });
  }
});

// qr-scanner part
app.get("/:email", auth, async (req, res) => {
  try {
    const userEmail = req.params.email;
    const result = await QRScanner.find({ username: userEmail });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: "Something went wrong!" });
  }
});

app.post("/api/v1/qrscanner/insert", auth, async (req, res) => {
  try {
    const { content, date, username } = req.body;

    const newQRScannerData = new QRScanner({
      content,
      date,
      username,
    });

    await newQRScannerData.save();

    res.json({ message: "Data inserted successfully" });
  } catch (error) {
    res.status(500).json({ error: "Something went wrong!" });
  }
});

app.delete("/api/v1/qrscanner/:index", auth, async (req, res) => {
  try {
    const id = req.params.index;
    console.log(id)

    const result = await QRScanner.findByIdAndDelete(id);

    if (!result) {
      return res.status(404).json({ error: "No rows deleted" });
    }

    res.json({ message: "Data deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: "Something went wrong!" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
