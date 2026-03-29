import { motion } from 'framer-motion';
import { Link, NavLink } from 'react-router-dom';

const links = [
  { to: '/', label: 'Home' },
  { to: '/scan', label: 'Scan' },
  { to: '/history', label: 'History' },
  { to: '/about', label: 'About' },
];

export function Navbar() {
  return (
    <header className="sticky top-0 z-40 border-b border-cyan-500/15 bg-slate-950/70 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 md:px-8">
        <Link to="/" className="flex items-center gap-3">
          <motion.div
            initial={{ scale: 0.9, opacity: 0.7 }}
            animate={{ scale: 1, opacity: 1 }}
            className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10 text-lg font-bold text-cyan-300 shadow-[0_0_32px_rgba(34,211,238,0.18)]"
          >
            PD
          </motion.div>
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-cyan-300/80">Cyber Defense</p>
            <p className="text-sm font-semibold text-white">Phishing Detector</p>
          </div>
        </Link>
        <nav className="flex items-center gap-2 rounded-full border border-white/10 bg-white/5 p-1">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) =>
                `rounded-full px-4 py-2 text-sm transition ${
                  isActive ? 'bg-cyan-400 text-slate-950' : 'text-slate-300 hover:bg-white/8 hover:text-white'
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>
      </div>
    </header>
  );
}
