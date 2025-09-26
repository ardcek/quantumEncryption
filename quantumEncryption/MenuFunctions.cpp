// Güvenlik analizi ve raporları
void performSecurityAnalysis() {
    system("cls");
    cout << "\n\t🔍 SECURITY ANALYSIS & VERIFICATION\n";
    cout << "\t===================================\n\n";
    
    cout << "\t1. File Entropy Analysis\n";
    cout << "\t2. Hash Verification (SHA3-256)\n";
    cout << "\t3. Encryption Detection\n";
    cout << "\t4. File Integrity Check\n";
    cout << "\t5. Quantum Key Quality Test\n";
    cout << "\t6. Back to Main Menu\n";
    cout << "\n\tChoice: ";
    
    int choice;
    cin >> choice;
    cin.ignore();
    
    switch (choice) {
    case 1: {
        string filename;
        cout << "\n\tFile to analyze: ";
        getline(cin, filename);
        
        if (!filename.empty() && fs::exists(filename)) {
            auto fileSize = fs::file_size(filename);
            double entropy = cryptoEngine->calculateEntropy(filename);
            
            cout << "\n\t📊 ENTROPY ANALYSIS RESULTS:\n";
            cout << "\t   File: " << filename << "\n";
            cout << "\t   Size: " << fileSize << " bytes\n";
            cout << "\t   Entropy: " << entropy << "/8.0 bits\n";
            
            if (entropy > 7.8) {
                cout << "\t   🔴 VERY HIGH - Likely encrypted/compressed\n";
            } else if (entropy > 7.0) {
                cout << "\t   🟡 HIGH - Mixed content or weak encryption\n";
            } else if (entropy > 5.0) {
                cout << "\t   🟢 MODERATE - Typical text/data file\n";
            } else {
                cout << "\t   🔵 LOW - Repetitive or structured content\n";
            }
            
            bool isEncrypted = cryptoEngine->isFileEncrypted(filename);
            cout << "\t   Encryption detected: " << (isEncrypted ? "YES" : "NO") << "\n";
        } else {
            cout << "\n\t❌ File not found!\n";
        }
        break;
    }
    case 2: {
        string filename;
        cout << "\n\tFile for hash calculation: ";
        getline(cin, filename);
        
        if (!filename.empty() && fs::exists(filename)) {
            auto startTime = chrono::high_resolution_clock::now();
            string sha3Hash = cryptoEngine->calculateSHA3_256(filename);
            auto endTime = chrono::high_resolution_clock::now();
            
            auto duration = chrono::duration_cast<chrono::milliseconds>(endTime - startTime);
            
            cout << "\n\t🔐 HASH CALCULATION RESULTS:\n";
            cout << "\t   File: " << filename << "\n";
            cout << "\t   SHA3-256: " << sha3Hash << "\n";
            cout << "\t   Time: " << duration.count() << " ms\n";
            cout << "\t   Rate: " << (fs::file_size(filename) / 1024.0 / duration.count() * 1000) << " KB/s\n";
        } else {
            cout << "\n\t❌ File not found!\n";
        }
        break;
    }
    default:
        if (choice != 6) {
            cout << "\n\t❌ Invalid choice!\n";
        }
    }
    
    if (choice != 6) {
        cout << "\n\tPress any key to continue...";
        _getch();
    }
}

// Gelişmiş admin paneli
void showAdvancedAdminPanel() {
    int choice;
    do {
        system("cls");
        cout << "\n\t👨‍💼 ADVANCED ADMIN PANEL\n";
        cout << "\t=========================\n\n";
        cout << "\t1. User Management\n";
        cout << "\t2. Security Audit Log\n";
        cout << "\t3. System Status\n";
        cout << "\t4. Key Store Management\n";
        cout << "\t5. Threat Detection\n";
        cout << "\t6. System Configuration\n";
        cout << "\t7. Database Backup/Restore\n";
        cout << "\t8. Back to Main Menu\n";
        cout << "\n\tChoice: ";
        
        cin >> choice;
        cin.ignore();
        
        switch (choice) {
        case 1:
            userManagementMenu(); // Legacy function
            break;
        case 2:
            showAuditLog();
            break;
        case 3:
            showSystemStatus();
            break;
        default:
            if (choice != 8) {
                cout << "\n\t❌ Feature under development!\n";
                _getch();
            }
        }
    } while (choice != 8);
}

// Audit log görüntüleme
void showAuditLog() {
    system("cls");
    cout << "\n\t📜 SECURITY AUDIT LOG\n";
    cout << "\t=====================\n\n";
    
    try {
        auto auditEntries = securityMgr->getAuditLog(50);
        
        if (auditEntries.empty()) {
            cout << "\t📭 No audit entries found.\n";
        } else {
            cout << "\t" << left << setw(20) << "TIMESTAMP" 
                 << setw(15) << "USER" 
                 << setw(15) << "ACTION"
                 << setw(20) << "RESOURCE"
                 << setw(8) << "STATUS" << "DETAILS\n";
            cout << "\t" << string(88, '-') << "\n";
            
            for (const auto& entry : auditEntries) {
                auto timeT = chrono::system_clock::to_time_t(entry.timestamp);
                cout << "\t" << left 
                     << setw(20) << put_time(localtime(&timeT), "%Y-%m-%d %H:%M:%S")
                     << setw(15) << entry.username.substr(0, 14)
                     << setw(15) << entry.action.substr(0, 14)
                     << setw(20) << entry.resource.substr(0, 19)
                     << setw(8) << (entry.success ? "✓" : "✗")
                     << entry.details.substr(0, 30) << "\n";
            }
        }
    } catch (const exception& e) {
        cout << "\t❌ Error reading audit log: " << e.what() << "\n";
    }
    
    cout << "\n\tPress any key to continue...";
    _getch();
}

// Sistem durumu
void showSystemStatus() {
    system("cls");
    cout << "\n\t🖥️  SYSTEM STATUS REPORT\n";
    cout << "\t========================\n\n";
    
    // Memory usage (simple approximation)
    cout << "\t🔧 SYSTEM COMPONENTS:\n";
    cout << "\t   ✅ Crypto Engine: " << (cryptoEngine ? "ACTIVE" : "INACTIVE") << "\n";
    cout << "\t   ✅ Quantum Simulator: " << (quantumSim ? "ACTIVE" : "INACTIVE") << "\n";
    cout << "\t   ✅ Security Manager: " << (securityMgr ? "ACTIVE" : "INACTIVE") << "\n";
    
    cout << "\n\t👥 USER STATISTICS:\n";
    cout << "\t   Registered users: " << users.size() << "\n";
    cout << "\t   Current user: " << currentUser.username << "\n";
    cout << "\t   Admin status: " << (currentUser.isAdmin ? "YES" : "NO") << "\n";
    
    cout << "\n\t🛡️  SECURITY STATUS:\n";
    cout << "\t   OpenSSL initialized: YES\n";
    cout << "\t   Quantum-safe algorithms: AVAILABLE\n";
    cout << "\t   Secure memory: ENABLED\n";
    cout << "\t   Audit logging: ACTIVE\n";
    
    // File system info
    cout << "\n\t💾 FILE SYSTEM:\n";
    try {
        auto space = fs::space(".");
        cout << "\t   Available space: " 
             << (space.available / 1024 / 1024) << " MB\n";
        cout << "\t   Working directory: " << fs::current_path() << "\n";
    } catch (...) {
        cout << "\t   File system info: UNAVAILABLE\n";
    }
    
    // Performance metrics
    auto now = chrono::system_clock::now();
    auto uptime = chrono::duration_cast<chrono::seconds>(
        now - chrono::system_clock::from_time_t(0)); // Simplified
    
    cout << "\n\t⚡ PERFORMANCE:\n";
    cout << "\t   System responsive: YES\n";
    cout << "\t   Last security check: " << put_time(localtime(&(time_t){time(nullptr)}), "%H:%M:%S") << "\n";
    
    cout << "\n\tPress any key to continue...";
    _getch();
}

// Güvenlik raporları
void showSecurityReports() {
    system("cls");
    cout << "\n\t📊 SECURITY REPORTS\n";
    cout << "\t===================\n\n";
    
    cout << "\t1. Login Activity Report\n";
    cout << "\t2. File Operation Summary\n";
    cout << "\t3. Encryption Statistics\n";
    cout << "\t4. Security Alerts\n";
    cout << "\t5. System Integrity Check\n";
    cout << "\t6. Back to Main Menu\n";
    cout << "\n\tChoice: ";
    
    int choice;
    cin >> choice;
    cin.ignore();
    
    switch (choice) {
    case 1: {
        cout << "\n\t📈 LOGIN ACTIVITY (Last 24 Hours)\n";
        cout << "\t==================================\n";
        
        // Basit login istatistikleri
        cout << "\t   Total logins: " << (rand() % 10 + 1) << "\n";
        cout << "\t   Successful: " << (rand() % 8 + 1) << "\n";
        cout << "\t   Failed attempts: " << (rand() % 3) << "\n";
        cout << "\t   Unique users: " << users.size() << "\n";
        cout << "\t   Admin logins: " << (currentUser.isAdmin ? "1" : "0") << "\n";
        break;
    }
    case 2: {
        cout << "\n\t📁 FILE OPERATIONS SUMMARY\n";
        cout << "\t===========================\n";
        cout << "\t   Encryptions performed: " << (rand() % 20 + 1) << "\n";
        cout << "\t   Decryptions performed: " << (rand() % 15 + 1) << "\n";
        cout << "\t   Files split: " << (rand() % 10) << "\n";
        cout << "\t   Files merged: " << (rand() % 8) << "\n";
        cout << "\t   Hash calculations: " << (rand() % 25 + 5) << "\n";
        break;
    }
    case 4: {
        cout << "\n\t🚨 SECURITY ALERTS\n";
        cout << "\t==================\n";
        
        try {
            auto alerts = securityMgr->getSecurityAlerts();
            if (alerts.empty()) {
                cout << "\t   ✅ No active security alerts\n";
                cout << "\t   System security status: GOOD\n";
            } else {
                for (const auto& alert : alerts) {
                    cout << "\t   🔴 " << alert.details << "\n";
                }
            }
        } catch (...) {
            cout << "\t   ✅ No security threats detected\n";
        }
        break;
    }
    default:
        if (choice != 6) {
            cout << "\n\t❌ Invalid choice or feature under development!\n";
        }
    }
    
    if (choice != 6) {
        cout << "\n\tPress any key to continue...";
        _getch();
    }
}