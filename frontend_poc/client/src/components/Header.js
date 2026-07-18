import React from "react";
import { Link } from "react-router-dom";

const Header = () => {
  return (
    <header className="bg-gradient-to-r from-indigo-700 to-blue-600 text-white shadow-lg">
      <div className="container mx-auto p-4">
        <div className="flex justify-between items-center">
          <Link to="/" className="text-2xl font-bold">
            Smart Contract Vulnerability Analyzer
          </Link>
          <nav>
            <ul className="flex space-x-4">
              <li>
                <Link to="/" className="hover:text-blue-200">
                  Home
                </Link>
              </li>
              <li>
                <a
                  href="https://github.com/yourusername/smart-contract-analyzer"
                  target="_blank"
                  rel="noreferrer"
                  className="hover:text-blue-200"
                >
                  GitHub
                </a>
              </li>
            </ul>
          </nav>
        </div>
      </div>
    </header>
  );
};

export default Header;
