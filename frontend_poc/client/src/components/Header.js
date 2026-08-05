import React from "react";
import { Link, NavLink } from "react-router-dom";
import { FileText, GitFork, Home, Shield } from "lucide-react";
import logo from "../assets/SmartGuardLogo.png";

const Header = () => {
  return (
    <header className="site-header">
      <div className="site-header-inner">
        <Link to="/" className="brand-link">
          <img src={logo} alt="SmartGuard AI logo" className="brand-logo" />
          <span className="brand-copy"><span className="brand-name">SmartGuard <em>AI</em></span><small>Secure. Analyze. Protect.</small></span>
        </Link>
        <nav aria-label="Primary navigation">
          <ul className="site-nav">
            <li><NavLink to="/" end className={({ isActive }) => `nav-link ${isActive ? "is-active" : ""}`}><Home size={17} />Home</NavLink></li>
            <li><NavLink to="/vulnerabilities" className={({ isActive }) => `nav-link ${isActive ? "is-active" : ""}`}><Shield size={17} />Vulnerabilities</NavLink></li>
            <li><NavLink to="/secure-generator" className={({ isActive }) => `nav-link ${isActive ? "is-active" : ""}`}><FileText size={17} />Secure Contract Generator</NavLink></li>
            <li><a href="https://github.com/sayeedur007-design/SmartContractGuardian" target="_blank" rel="noopener noreferrer" className="nav-link"><GitFork size={18} />GitHub</a></li>
          </ul>
        </nav>
      </div>
    </header>
  );
};

export default Header;
