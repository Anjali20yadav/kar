const multer = require("multer")


const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB
    },
    fileFilter: (req, file, cb) => {
        const allowedMimeTypes = new Set([
            "application/pdf",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/msword"
        ])

        if (!allowedMimeTypes.has(file.mimetype)) {
            const err = new Error("Unsupported file type. Please upload a PDF or DOCX file.")
            err.code = "UNSUPPORTED_FILE_TYPE"
            return cb(err, false)
        }

        cb(null, true)
    },
})


module.exports = upload