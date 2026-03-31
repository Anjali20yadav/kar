const pdfParse = require("pdf-parse")
const { generateInterviewReport, generateResumePdf } = require("../services/ai.service")
const interviewReportModel = require("../models/interviewReport.model")




/**
 * @description Controller to generate interview report based on user self description, resume and job description.
 */
async function generateInterViewReportController(req, res) {

    try {
        const { selfDescription, jobDescription } = req.body

        // Check if job description is provided (required)
        if (!jobDescription) {
            return res.status(400).json({
                message: "Job description is required."
            })
        }

        // Check if at least one of self description or resume is provided
        if (!selfDescription && !req.file) {
            return res.status(400).json({
                message: "Either self description or resume (or both) is required."
            })
        }

        // Validate file type if resume is uploaded
        if (req.file && req.file.mimetype !== "application/pdf") {
            return res.status(400).json({
                message: "Only PDF resumes are supported right now. Please upload a PDF file."
            })
        }

        let resumeText = ""
        if (req.file) {
            try {
                const parsed = await pdfParse(req.file.buffer)
                resumeText = parsed?.text || ""
            } catch (e) {
                return res.status(400).json({
                    message: "Could not read this PDF. Please try a different PDF file."
                })
            }
        }

        const interViewReportByAi = await generateInterviewReport({
            resume: resumeText,
            selfDescription,
            jobDescription
        })

        const interviewReport = await interviewReportModel.create({
            user: req.user.id,
            resume: resumeText,
            selfDescription,
            jobDescription,
            ...interViewReportByAi
        })

        res.status(201).json({
            message: "Interview report generated successfully.",
            interviewReport
        })
    } catch (err) {
        res.status(500).json({
            message: "Failed to generate interview report."
        })
    }

}

/**
 * @description Controller to get interview report by interviewId.
 */
async function getInterviewReportByIdController(req, res) {

    const { interviewId } = req.params

    const interviewReport = await interviewReportModel.findOne({ _id: interviewId, user: req.user.id })

    if (!interviewReport) {
        return res.status(404).json({
            message: "Interview report not found."
        })
    }

    res.status(200).json({
        message: "Interview report fetched successfully.",
        interviewReport
    })
}


/** 
 * @description Controller to get all interview reports of logged in user.
 */
async function getAllInterviewReportsController(req, res) {
    const interviewReports = await interviewReportModel.find({ user: req.user.id }).sort({ createdAt: -1 }).select("-resume -selfDescription -jobDescription -__v -technicalQuestions -behavioralQuestions -skillGaps -preparationPlan")

    res.status(200).json({
        message: "Interview reports fetched successfully.",
        interviewReports
    })
}

/**
 * @description Controller to delete an interview report by interviewId.
 */
async function deleteInterviewReportController(req, res) {
    const { interviewId } = req.params

    const report = await interviewReportModel.findOne({ _id: interviewId, user: req.user.id })
    if (!report) {
        return res.status(404).json({
            message: "Interview report not found."
        })
    }

    await interviewReportModel.deleteOne({ _id: interviewId, user: req.user.id })

    res.status(200).json({
        message: "Interview report deleted successfully."
    })
}


/**
 * @description Controller to generate resume PDF based on user self description, resume and job description.
 */
async function generateResumePdfController(req, res) {
    const { interviewReportId } = req.params

    const interviewReport = await interviewReportModel.findById(interviewReportId)

    if (!interviewReport) {
        return res.status(404).json({
            message: "Interview report not found."
        })
    }

    const { resume, jobDescription, selfDescription } = interviewReport

    const pdfBuffer = await generateResumePdf({ resume, jobDescription, selfDescription })

    res.set({
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename=resume_${interviewReportId}.pdf`
    })

    res.send(pdfBuffer)
}

module.exports = { generateInterViewReportController, getInterviewReportByIdController, getAllInterviewReportsController, deleteInterviewReportController, generateResumePdfController }