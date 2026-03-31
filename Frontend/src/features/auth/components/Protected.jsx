import { useAuth } from "../hooks/useAuth";
import { Navigate } from "react-router";
import React from 'react'

const Protected = ({children}) => {
    const { loading, user, handleLogout } = useAuth()


    if(loading){
        return (<main><h1>Loading...</h1></main>)
    }

    if(!user){
        return <Navigate to={'/login'} />
    }
    
    return (
        <>
            <button type="button" className="logout-btn" onClick={handleLogout}>
                Logout
            </button>
            {children}
        </>
    )
}

export default Protected