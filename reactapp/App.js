import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./Components/AuthContext";
import NavbarSwitcher from "./Components/NavbarSwitcher";
import Login from "./Components/Login";
import Signup from "./Components/Signup";
import HomePage from "./Components/HomePage";
import ErrorPage from "./Components/ErrorPage";

import ViewPlace from "./GuideComponents/ViewPlace";
import PlaceForm from "./GuideComponents/PlaceForm"; 

import TravellerPlaces from "./TravellerComponents/TravellerViewPlace";

import ApprovalsTable from "./Admin/ApprovalsTable";

function AppLoader() {
  return <div style={{ padding: 24, textAlign: "center" }}>Loading…</div>;
}


function GuideGate({ children }) {
  const { auth, ready } = useAuth();
  if (!ready) return <AppLoader />;
  if (!auth) return <Navigate to="/login" replace />;
  if (auth.role !== "guide") {
    return auth.role === "traveller"
      ? <Navigate to="/traveller/places" replace />
      : <Navigate to="/home" replace />;
  }
  return children;
}

function TravellerGate({ children }) {
  const { auth, ready } = useAuth();
  if (!ready) return <AppLoader />;
  if (!auth) return <Navigate to="/login" replace />;
  if (auth.role !== "traveller") {
    return auth.role === "guide"
      ? <Navigate to="/places" replace />
      : <Navigate to="/home" replace />;
  }
  return children;
}

function AdminGate({ children }) {
  const { auth, ready } = useAuth();
  if (!ready) return <AppLoader />;
  if (!auth) return <Navigate to="/login" replace />;
  if (auth.role !== "admin") {
    if (auth.role === "guide") return <Navigate to="/places" replace />;
    if (auth.role === "traveller") return <Navigate to="/traveller/places" replace />;
    return <Navigate to="/home" replace />;
  }
  return children;
}

function PublicOnly({ children }) {
  const { auth, ready } = useAuth();
  if (!ready) return <AppLoader />;
  if (auth?.role === "admin") return <Navigate to="/admin/home" replace />;
  if (auth?.role === "guide") return <Navigate to="/places" replace />;
  if (auth?.role === "traveller") return <Navigate to="/traveller/places" replace />;
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <Router>
        
        <NavbarSwitcher />

        <Routes>
          
          <Route path="/home" element={<HomePage />} />
          <Route
            path="/login"
            element={
              <PublicOnly>
                <Login />
              </PublicOnly>
            }
          />
          <Route
            path="/signup"
            element={
              <PublicOnly>
                <Signup />
              </PublicOnly>
            }
          />

          
          <Route path="/traveller" element={<Navigate to="/traveller/places" replace />} />
          <Route
            path="/traveller/places"
            element={
              <TravellerGate>
                <TravellerPlaces />
              </TravellerGate>
            }
          />
          
          <Route
            path="/places"
            element={
              <GuideGate>
                <ViewPlace /> 
              </GuideGate>
            }
          />
          <Route
            path="/places/new"
            element={
              <GuideGate>
                <PlaceForm mode="add" />
              </GuideGate>
            }
          />
          <Route
            path="/places/:id/edit"
            element={
              <GuideGate>
                <PlaceForm mode="edit" />
              </GuideGate>
            }
          />

          <Route path="/admin" element={<Navigate to="/admin/home" replace />} />
          <Route
            path="/admin/home"
            element={
              <AdminGate>
                <ApprovalsTable />
              </AdminGate>
            }
          />

          <Route path="/" element={<Navigate to="/home" replace />} />
          <Route path="*" element={<ErrorPage />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}
