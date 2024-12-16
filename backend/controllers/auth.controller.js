import { redis } from "../lib/redis.js";
import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

// Ensure that environment variables are loaded
dotenv.config(); // Load environment variables from .env file

// Debugging: Log JWT secrets to ensure they are loaded
console.log("ACCESS_TOKEN_SECRET:", process.env.ACCESS_TOKEN_SECRET);
console.log("REFRESH_TOKEN_SECRET:", process.env.REFRESH_TOKEN_SECRET);

const generateTokens = (userId) => {
    // Ensure JWT secrets are available
    if (!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
        throw new Error("JWT secrets are not defined in environment variables.");
    }

    // Create JWT tokens
    const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "15m", // Access token expires in 15 minutes
    });

    const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: "7d", // Refresh token expires in 7 days
    });

    return { accessToken, refreshToken };
};

const storeRefreshToken = async (userId, refreshToken) => {
    // Store refresh token in Redis with a 7-day expiration
    await redis.set(`refresh_token:${userId}`, refreshToken, "EX", 7 * 24 * 60 * 60);
};

const setCookies = (res, accessToken, refreshToken) => {
    // Set cookies for access and refresh tokens
    res.cookie("accessToken", accessToken, {
        httpOnly: true, // Prevent XSS attacks
        secure: process.env.NODE_ENV === "production", // Use secure cookies in production
        sameSite: "strict", // Prevent CSRF attacks
        maxAge: 15 * 60 * 1000, // Access token is valid for 15 minutes
    });

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true, // Prevent XSS attacks
        secure: process.env.NODE_ENV === "production", // Use secure cookies in production
        sameSite: "strict", // Prevent CSRF attacks
        maxAge: 7 * 24 * 60 * 60 * 1000, // Refresh token is valid for 7 days
    });
};

export const signup = async (req, res) => {
    const { email, password, name } = req.body;
    try {
        // Check if user already exists
        const userExists = await User.findOne({ email });

        if (userExists) {
            return res.status(400).json({ message: "User already exists" });
        }

        // Create new user
        const user = await User.create({ name, email, password });

        // Generate JWT tokens for user
        const { accessToken, refreshToken } = generateTokens(user._id);

        // Store refresh token in Redis
        await storeRefreshToken(user._id, refreshToken);

        // Set cookies with tokens
        setCookies(res, accessToken, refreshToken);

        // Send response with user data
        res.status(201).json({
            _id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
        });
    } catch (error) {
        console.log("Error in signup controller", error.message);
        res.status(500).json({ message: error.message });
    }
};

export const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user by email
        const user = await User.findOne({ email });

        // Check if password matches
        if (user && (await user.comparePassword(password))) {
            // Generate JWT tokens
            const { accessToken, refreshToken } = generateTokens(user._id);

            // Store refresh token in Redis
            await storeRefreshToken(user._id, refreshToken);

            // Set cookies with tokens
            setCookies(res, accessToken, refreshToken);

            // Send response with user data
            res.json({
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
            });
        } else {
            res.status(400).json({ message: "Invalid email or password" });
        }
    } catch (error) {
        console.log("Error in login controller", error.message);
        res.status(500).json({ message: error.message });
    }
};

export const logout = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (refreshToken) {
            const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
            await redis.del(`refresh_token:${decoded.userId}`);
        }

        // Clear cookies
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        res.json({ message: "Logged out successfully" });
    } catch (error) {
        console.log("Error in logout controller", error.message);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

export const refreshToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(401).json({ message: "No refresh token provided" });
        }

        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const storedToken = await redis.get(`refresh_token:${decoded.userId}`);

        // Validate if the stored token matches the received token
        if (storedToken !== refreshToken) {
            return res.status(401).json({ message: "Invalid refresh token" });
        }

        // Generate new access token
        const accessToken = jwt.sign({ userId: decoded.userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });

        // Set new access token in cookies
        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 15 * 60 * 1000,
        });

        res.json({ message: "Token refreshed successfully" });
    } catch (error) {
        console.log("Error in refreshToken controller", error.message);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

export const getProfile = async (req, res) => {
    try {
        res.json(req.user);
    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
};
