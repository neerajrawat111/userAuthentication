const { prisma } = require("../db/config");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require('../constants/constant.js');
const dotenv = require("dotenv");
dotenv.config();

// const JWT_SECRET = process.env.JWT_SECRET; 

const signup = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ error: "Name, email, and password are required" });
  }

  try {
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(400).json({ error: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });
    return res
      .status(201)
      .json({ message: "User created successfully", userId: user.id });
  } catch (error) {
    return res.status(500).json({ error: "Server error" });
  }
}

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { email: email },
    });


    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET);

    return res.status(200).json({userdata:user ,accesstoken: token });
  } catch (error) {
    return res.status(500).json({ error: "Server error" });
  }
};

module.exports = { signup, login };
