import React from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import DashboardPage from './pages/DashboardPage';
import FlagDetailPage from './pages/FlagDetailPage';
import NewFlagPage from './pages/NewFlagPage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import ProfilePage from './pages/ProfilePage';
import Header from './components/Header';
import ProtectedRoute from './components/ProtectedRoute';

const PrivateLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <>
    <Header />
    <main className="p-4 sm:p-8 lg:p-12">{children}</main>
  </>
);

const App: React.FC = () => {
  return (
    <HashRouter>
      <div className="min-h-screen bg-transparent font-sans text-gray-900 dark:text-gray-200">
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          
          <Route path="/*" element={
            <ProtectedRoute>
              <PrivateLayout>
                <Routes>
                  <Route path="/flags" element={<DashboardPage />} />
                  <Route path="/flags/new" element={<NewFlagPage />} />
                  <Route path="/flags/:flagKey" element={<FlagDetailPage />} />
                  <Route path="/profile" element={<ProfilePage />} />
                  <Route path="*" element={<Navigate to="/flags" replace />} />
                </Routes>
              </PrivateLayout>
            </ProtectedRoute>
          } />
        </Routes>
      </div>
    </HashRouter>
  );
};

export default App;