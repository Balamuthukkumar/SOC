import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import './index.css'
import { AuthProvider, useAuth } from './auth'
import Layout from './components/Layout'
import { Spinner } from './components/ui'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import Assets from './pages/Assets'
import Events from './pages/Events'
import Cases from './pages/Cases'
import CaseDetail from './pages/CaseDetail'
import HuntLab from './pages/HuntLab'
import MitreMap from './pages/MitreMap'
import ResponsePlans from './pages/ResponsePlans'
import Validation from './pages/Validation'
import OTDiscovery from './pages/OTDiscovery'
import Compliance from './pages/Compliance'
import SettingsPage from './pages/Settings'

function Protected() {
  const { user, ready } = useAuth()
  if (!ready) return <Spinner />
  return user ? <Layout /> : <Navigate to="/login" replace />
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter basename="/app">
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<Protected />}>
            <Route index element={<Dashboard />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="assets" element={<Assets />} />
            <Route path="events" element={<Events />} />
            <Route path="cases" element={<Cases />} />
            <Route path="cases/:id" element={<CaseDetail />} />
            <Route path="hunt" element={<HuntLab />} />
            <Route path="mitre" element={<MitreMap />} />
            <Route path="response" element={<ResponsePlans />} />
            <Route path="validation" element={<Validation />} />
            <Route path="ot" element={<OTDiscovery />} />
            <Route path="compliance" element={<Compliance />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
