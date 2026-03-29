import { createBrowserRouter } from 'react-router-dom';
import { AppShell } from '../components/AppShell';
import { ErrorBoundaryPage } from '../pages/ErrorBoundaryPage';
import { HomePage } from '../pages/HomePage';
import { NotFoundPage } from '../pages/NotFoundPage';

export const router = createBrowserRouter([
  {
    path: '/',
    element: <AppShell />,
    errorElement: <ErrorBoundaryPage />,
    children: [
      { index: true, element: <HomePage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
]);
