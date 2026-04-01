const express = require("express")
const cookieParser = require("cookie-parser")
const cors = require("cors")
const multer = require("multer")

const app = express()

app.use(express.json())
app.use(cookieParser())

app.use(cors({
    origin: [
        "http://localhost:5173",
        "https://kar-black.vercel.app"   // Frontend URL (Vercel)
    ],
    credentials: true
}))

/* require all the routes here */
const authRouter = require("./routes/auth.routes")
const interviewRouter = require("./routes/interview.routes")


/* using all the routes here */
app.use("/api/auth", authRouter)
app.use("/api/interview", interviewRouter)

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                message: "Resume file is too large. Max size is 10MB."
            })
        }
        return res.status(400).json({ message: err.message })
    }

    if (err && err.code === "UNSUPPORTED_FILE_TYPE") {
        return res.status(400).json({ message: err.message })
    }

    if (err) {
        return res.status(500).json({
            message: "Server error while uploading resume.",
        })
    }

    next()
})



module.exports = app