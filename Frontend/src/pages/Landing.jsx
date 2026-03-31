import React from "react"
import { Link, Navigate } from "react-router"
import { useAuth } from "../features/auth/hooks/useAuth"
import "./landing.scss"

const Landing = () => {
    const { user, loading } = useAuth()

    if (loading) {
        return (
            <main className="landing">
                <div className="landing__shell">
                    <h1>Loading...</h1>
                </div>
            </main>
        )
    }

    if (user) {
        return <Navigate to="/app" />
    }

    return (
        <main className="landing">
            <div className="landing__shell">
                <header className="landing__header">
                    <p className="landing__eyebrow">AI Interview Coach</p>
                    <h1 className="landing__title">
                        Turn your resume + job description into a{" "}
                        <span className="landing__accent">personalized interview plan</span>
                    </h1>
                    <p className="landing__subtitle">
                        Upload your resume, paste the target job description, and get a structured plan with match score,
                        technical questions, behavioral questions, and a day-wise roadmap.
                    </p>
                </header>

                <div className="landing__cta">
                    <Link className="button primary-button" to="/register">Get started</Link>
                    <Link className="landing__secondary" to="/login">I already have an account</Link>
                </div>

                <section className="landing__grid">
                    <div className="landing__card">
                        <h3>Upload & analyze</h3>
                        <p>We extract the important details from your PDF resume and compare it with the job.</p>
                    </div>
                    <div className="landing__card">
                        <h3>Practice smarter</h3>
                        <p>Get targeted questions with intent and model answers—focused on what interviewers ask.</p>
                    </div>
                    <div className="landing__card">
                        <h3>Follow a roadmap</h3>
                        <p>Use a day-wise prep plan to close gaps and improve your match score quickly.</p>
                    </div>
                </section>
            </div>
        </main>
    )
}

export default Landing

