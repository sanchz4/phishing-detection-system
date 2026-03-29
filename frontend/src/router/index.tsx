import { createBrowserRouter } from 'react-router-dom';
import { AppShell } from '../components/AppShell';
import { AboutPage } from '../pages/AboutPage';
import { ErrorBoundaryPage } from '../pages/ErrorBoundaryPage';
import { HistoryPage } from '../pages/HistoryPage';
import { LandingPage } from '../pages/LandingPage';
import { NotFoundPage } from '../pages/NotFoundPage';
import { ScanPage } from '../pages/ScanPage';

export const router = createBrowserRouter([
  {
    path: '/',
    element: <AppShell />,
    errorElement: <ErrorBoundaryPage />,
    children: [
      { index: true, element: <LandingPage /> },
      { path: 'scan', element: <ScanPage /> },
      { path: 'history', element: <HistoryPage /> },
      { path: 'about', element: <AboutPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
]);
