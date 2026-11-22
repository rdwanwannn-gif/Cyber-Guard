import type { LanguageCode } from '../lib/types';

export interface Translations {
  brandName: string;
  nav: {
    overview: string;
    threats: string;
    logs: string;
    siem: string;
    reports: string;
    mfa: string;
    users: string;
    complaints: string;
  };
  portal: {
    adminPortalBadge: string;
    userPortalBadge: string;
    adminPortalTitle: string;
    userPortalTitle: string;
    openUserPortal: string;
    openAdminPortal: string;
    switchToUserLink: string;
    switchToAdminLink: string;
    separateSessionHint: string;
    userPortalWaitAdmin: string;
    registerHintUserPortal: string;
  };
  complaints: {
    title: string;
    subtitle: string;
    categoryLabel: string;
    severityLabel: string;
    subjectLabel: string;
    subjectPlaceholder: string;
    descriptionLabel: string;
    descriptionPlaceholder: string;
    submitBtn: string;
    submittedBanner: string;
    myHistoryTitle: string;
    emptyHistory: string;
    adminReplyLabel: string;
    statusOpen: string;
    statusInReview: string;
    statusResolved: string;
    catAccessMfa: string;
    catSecurityIncident: string;
    catPerformanceBug: string;
    catPolicyRequest: string;
    catOther: string;
  };
  auth: {
    setupTitle: string;
    setupSubtitle: string;
    loginTitle: string;
    loginSubtitle: string;
    registerTitle: string;
    registerSubtitle: string;
    tabSignIn: string;
    tabRegister: string;
    mfaTitle: string;
    mfaSubtitle: string;
    fullNameLabel: string;
    departmentLabel: string;
    deviceNameLabel: string;
    deviceNamePlaceholder: string;
    emailLabel: string;
    accountEmailLabel: string;
    passwordLabel: string;
    createAdminBtn: string;
    signInBtn: string;
    registerBtn: string;
    registerSuccessTitle: string;
    registerSuccessDesc: string;
    backToSignIn: string;
    mfaCodeLabel: string;
    verifyMfaBtn: string;
    enrollSecretLabel: string;
    backupCodesLabel: string;
    generateHelperBtn: string;
    backToLogin: string;
    mfaProtectedNote: string;
    adminOtpTitle: string;
    adminOtpSubtitle: string;
    sendOtpBtn: string;
    otpVerifyTitle: string;
    otpVerifySubtitle: string;
    otpCodeLabel: string;
    verifyOtpBtn: string;
    resendOtpBtn: string;
    changeAdminEmailBtn: string;
    otpPreviewTitle: string;
    otpPreviewHint: string;
    fillOtpHelperBtn: string;
    otpSentEmailNotice: string;
  };
  topbar: {
    simulateProbe: string;
    notifications: string;
    markAllRead: string;
    noNotifications: string;
    lightMode: string;
    darkMode: string;
    signOut: string;
    wsConnected: string;
    wsReconnecting: string;
    simulatingLabel: string;
    viewerReadOnlyTip: string;
  };
  overview: {
    title: string;
    subtitle: string;
    kpiThroughput: string;
    kpiThreats: string;
    kpiEncryptedLogs: string;
    kpiClusterCapacity: string;
    chartTitle: string;
    chartSubtitle: string;
    inbound: string;
    outbound: string;
    blockedPps: string;
    protocolMix: string;
    recentThreats: string;
    viewAllThreats: string;
    blockIp: string;
    mitigate: string;
    automatedCount: string;
    globeTitle: string;
    globeSubtitle: string;
    pauseRotation: string;
    resumeRotation: string;
    resetView: string;
  };
  threats: {
    title: string;
    subtitle: string;
    searchPlaceholder: string;
    all: string;
    critical: string;
    high: string;
    medium: string;
    low: string;
    triggerScenario: string;
    incidentTable: string;
    sourceAsset: string;
    vectorTactic: string;
    severity: string;
    status: string;
    actions: string;
    blockIp: string;
    resolve: string;
    acknowledge: string;
    automationRulesTitle: string;
    addRuleBtn: string;
    ruleNamePlaceholder: string;
    minSeverity: string;
    ruleAction: string;
    saveRule: string;
    startDrill: string;
    stopDrill: string;
    drillRunning: string;
    wavesExecuted: string;
    viewDetails: string;
  };
  logs: {
    title: string;
    subtitle: string;
    activeKey: string;
    algorithm: string;
    verifyChain: string;
    rotateKey: string;
    decryptAll: string;
    hidePlaintext: string;
    chainVerifiedOk: string;
    chainBroken: string;
    sequence: string;
    timestamp: string;
    endpoint: string;
    ciphertextPreview: string;
    integrityHash: string;
    payloadStatus: string;
    encryptedLabel: string;
    decryptedLabel: string;
  };
  siem: {
    title: string;
    subtitle: string;
    connectorsTitle: string;
    testSync: string;
    payloadPreview: string;
    apiKeysTitle: string;
    keyLabelPlaceholder: string;
    createKeyBtn: string;
    copyOnceWarning: string;
    revokeBtn: string;
    thirdPartyTitle: string;
    complianceTitle: string;
    eventsSynced: string;
  };
  reports: {
    title: string;
    subtitle: string;
    weeklyReportsTitle: string;
    generateNow: string;
    downloadCsv: string;
    downloadJson: string;
    scheduleTitle: string;
    scheduleEnabled: string;
    dayLabel: string;
    timeUtcLabel: string;
    recipientsLabel: string;
    saveSchedule: string;
    scalabilityTitle: string;
    autoScaleToggle: string;
    maxNodesLabel: string;
    targetLoadLabel: string;
    stressTestStart: string;
    stressTestStop: string;
    activeNodes: string;
    kafkaBuffer: string;
    headroom: string;
  };
  mfa: {
    title: string;
    subtitle: string;
    statusTitle: string;
    mfaActiveLabel: string;
    totpStandard: string;
    policyDecryption: string;
    policyKeyRotation: string;
    backupCodesTitle: string;
    backupRemaining: string;
    regenerateBackupBtn: string;
    sessionsTitle: string;
    sessionEmail: string;
    sessionRole: string;
    sessionVerified: string;
  };
  users: {
    title: string;
    subtitle: string;
    kpiTotal: string;
    kpiPending: string;
    kpiActive: string;
    kpiRestricted: string;
    requireApprovalLabel: string;
    requireApprovalHint: string;
    searchPlaceholder: string;
    all: string;
    pending: string;
    active: string;
    suspended: string;
    blocked: string;
    userColumn: string;
    deviceColumn: string;
    roleColumn: string;
    statusColumn: string;
    controlsColumn: string;
    activateBtn: string;
    suspendBtn: string;
    blockBtn: string;
    resetMfaBtn: string;
    revokeSessionsBtn: string;
    flagIssueBtn: string;
    resolveIssueBtn: string;
    issueNotePlaceholder: string;
    saveIssueBtn: string;
    cancelBtn: string;
    emptyState: string;
    auditTitle: string;
    auditSubtitle: string;
    mfaEnrolled: string;
    mfaPending: string;
    activeSessions: string;
    tabAccounts: string;
    tabComplaints: string;
    complaintsEmpty: string;
    respondNotePlaceholder: string;
    markInReviewBtn: string;
    markResolvedBtn: string;
    sendReplyBtn: string;
    handledByLabel: string;
    viewComplaintsBtn: string;
  };
}

export const TRANSLATIONS: Record<LanguageCode, Translations> = {
  id: {
    brandName: 'SentinelGrid',
    nav: {
      overview: 'Ringkasan SOC',
      threats: 'Ancaman & Respon',
      logs: 'Log Terenkripsi E2E',
      siem: 'SIEM & Integrasi API',
      reports: 'Laporan & Skalabilitas',
      mfa: 'Autentikasi MFA',
      users: 'Kontrol Pengguna',
      complaints: 'Keluhan & Laporan',
    },
    portal: {
      adminPortalBadge: 'Portal Admin (/admin)',
      userPortalBadge: 'Portal Pengguna (/user)',
      adminPortalTitle: 'Portal Administrator',
      userPortalTitle: 'Portal Pengguna',
      openUserPortal: 'Buka Portal Pengguna (/user)',
      openAdminPortal: 'Buka Portal Admin (/admin)',
      switchToUserLink: 'Login / Daftar Pengguna → /user',
      switchToAdminLink: 'Login Admin → /admin',
      separateSessionHint: 'Sesi /admin dan /user terpisah otomatis sehingga tidak saling mengeluarkan.',
      userPortalWaitAdmin: 'Workspace Administrator belum diaktivasi. Aktifkan akun Admin utama terlebih dahulu di /admin.',
      registerHintUserPortal: 'Pendaftaran pengguna tim dan laporan keluhan dilakukan lewat link Portal Pengguna (/user).',
    },
    complaints: {
      title: 'Kirim Keluhan & Laporan ke Admin',
      subtitle: 'Setiap keluhan atau temuan masalah dari perangkat ini dikirim secara real-time langsung ke dasbor Admin.',
      categoryLabel: 'Kategori Keluhan',
      severityLabel: 'Tingkat Urgensi',
      subjectLabel: 'Judul / Ringkasan Keluhan',
      subjectPlaceholder: 'Contoh: Kendala akses MFA atau deteksi trafik mencurigakan...',
      descriptionLabel: 'Detail Masalah / Kronologi',
      descriptionPlaceholder: 'Jelaskan kendala, perangkat, atau indikasi masalah keamanan secara lengkap...',
      submitBtn: 'Kirim Keluhan ke Admin',
      submittedBanner: 'Keluhan berhasil dikirim ke akun Admin secara real-time.',
      myHistoryTitle: 'Riwayat Keluhan & Respon Admin',
      emptyHistory: 'Belum ada keluhan atau laporan yang Anda kirimkan.',
      adminReplyLabel: 'Respon Admin',
      statusOpen: 'Menunggu Admin',
      statusInReview: 'Ditinjau Admin',
      statusResolved: 'Selesai',
      catAccessMfa: 'Kendala Akses / MFA',
      catSecurityIncident: 'Anomali Jaringan / Ancaman',
      catPerformanceBug: 'Kinerja & Bug Sistem',
      catPolicyRequest: 'Permintaan Izin / Kebijakan',
      catOther: 'Lainnya',
    },
    auth: {
      setupTitle: 'Aktivasi Workspace Keamanan SOC',
      setupSubtitle: 'Tetapkan kredensial administrator pertama dan aktifkan autentikasi multifaktor (TOTP).',
      loginTitle: 'Masuk ke Konsol SentinelGrid',
      loginSubtitle: 'Akses terproteksi dengan verifikasi sandi dan autentikasi multifaktor.',
      registerTitle: 'Daftar Akun Pengguna Baru',
      registerSubtitle: 'Data pendaftaran perangkat ini otomatis dikirim ke Dasbor Kontrol Admin untuk persetujuan akses.',
      tabSignIn: 'Masuk',
      tabRegister: 'Daftar Akun',
      mfaTitle: 'Verifikasi Autentikasi Multifaktor',
      mfaSubtitle: 'Masukkan kode 6-digit dari aplikasi autentikator atau kode pemulihan cadangan.',
      fullNameLabel: 'Nama Lengkap',
      departmentLabel: 'Divisi / Tim',
      deviceNameLabel: 'Nama Perangkat (Terdeteksi Otomatis / Opsional)',
      deviceNamePlaceholder: 'Contoh: Samsung Galaxy S24 / Redmi Note 13 / Laptop Kantor',
      emailLabel: 'Email Administrator',
      accountEmailLabel: 'Email Pengguna',
      passwordLabel: 'Kata Sandi',
      createAdminBtn: 'Buat Akun & Lanjut ke MFA',
      signInBtn: 'Lanjutkan ke Verifikasi MFA',
      registerBtn: 'Kirim Pendaftaran ke Admin',
      registerSuccessTitle: 'Pendaftaran Terkirim ke Akun Admin',
      registerSuccessDesc: 'Akun Anda telah tercatat di sistem pusat dan masuk ke Dasbor Kontrol Admin. Hubungi Admin atau coba masuk setelah diaktifkan.',
      backToSignIn: 'Kembali ke Halaman Masuk',
      mfaCodeLabel: 'Kode TOTP 6-Digit / Kode Pemulihan',
      verifyMfaBtn: 'Verifikasi & Buka Dasbor',
      enrollSecretLabel: 'Kunci Rahasia TOTP (Base32)',
      backupCodesLabel: 'Kode Pemulihan Cadangan (Simpan Aman)',
      generateHelperBtn: 'Isi Kode TOTP Dari Kunci Aktivasi',
      backToLogin: 'Kembali ke Login',
      mfaProtectedNote: 'Sesi dilindungi token HMAC-SHA256 dan verifikasi OTP / TOTP RFC 6238.',
      adminOtpTitle: 'Masuk Admin dengan Kode OTP Email',
      adminOtpSubtitle: 'Cukup masukkan email administrator Anda. Kode OTP 6-digit dikirim ke email sebagai pengganti kata sandi.',
      sendOtpBtn: 'Kirim Kode OTP ke Email',
      otpVerifyTitle: 'Masukkan Kode OTP dari Email',
      otpVerifySubtitle: 'Periksa kode verifikasi 6-digit yang dikirim ke email administrator di bawah ini.',
      otpCodeLabel: 'Kode OTP Email (6-Digit)',
      verifyOtpBtn: 'Verifikasi OTP & Masuk Admin',
      resendOtpBtn: 'Kirim Ulang Kode OTP',
      changeAdminEmailBtn: 'Ganti Email Admin',
      otpPreviewTitle: 'Kotak Masuk OTP Sementara (Tanpa SMTP/Resend)',
      otpPreviewHint: 'Variabel RESEND_API_KEY belum dipasang di server. Gunakan kode OTP di bawah ini untuk langsung masuk:',
      fillOtpHelperBtn: 'Isi Kode OTP Otomatis',
      otpSentEmailNotice: 'Kode OTP 6-digit telah dikirim ke kotak masuk email Anda (berlaku 10 menit).',
    },
    topbar: {
      simulateProbe: 'Simulasi Serangan',
      notifications: 'Notifikasi Keamanan',
      markAllRead: 'Tandai Dibaca',
      noNotifications: 'Semua notifikasi telah ditinjau.',
      lightMode: 'Mode Terang',
      darkMode: 'Mode Gelap',
      signOut: 'Keluar',
      wsConnected: 'Aliran Real-Time Aktif',
      wsReconnecting: 'Menghubungkan Ulang...',
      simulatingLabel: 'Simulasi Aktif',
      viewerReadOnlyTip: 'Akses baca-saja (Viewer)',
    },
    overview: {
      title: 'Pemantauan Trafik & Ancaman Real-Time',
      subtitle: 'Telemetri paket jaringan langsung, deteksi anomali otomatis, dan status kapasitas klaster.',
      kpiThroughput: 'Trafik Jaringan Aktif',
      kpiThreats: 'Ancaman Terdeteksi',
      kpiEncryptedLogs: 'Log Terenkripsi AES-256',
      kpiClusterCapacity: 'Kapasitas Klaster',
      chartTitle: 'Aliran Trafik Jaringan Langsung',
      chartSubtitle: 'Throughput masuk dan keluar real-time (Gbps) serta paket diblokir.',
      inbound: 'Masuk (Inbound)',
      outbound: 'Keluar (Outbound)',
      blockedPps: 'Paket Diblokir',
      protocolMix: 'Distribusi Protokol',
      recentThreats: 'Deteksi Ancaman Terbaru',
      viewAllThreats: 'Buka Semua Ancaman',
      blockIp: 'Blokir IP',
      mitigate: 'Mitigasi',
      automatedCount: 'aturan aktif',
      globeTitle: 'Bola Dunia Ancaman Langsung',
      globeSubtitle: 'Seret untuk memutar · Rute serangan real-time ke Hub SOC Jakarta',
      pauseRotation: 'Jeda Rotasi Bumi',
      resumeRotation: 'Putar Bumi',
      resetView: 'Reset Posisi Bumi',
    },
    threats: {
      title: 'Deteksi Ancaman & Respon Otomatis',
      subtitle: 'Inspeksi insiden siber real-time, isolasi IP penyerang, dan orkestrasi notifikasi tim.',
      searchPlaceholder: 'Cari IP sumber, aset tujuan, atau ID signature...',
      all: 'Semua',
      critical: 'Kritis',
      high: 'Tinggi',
      medium: 'Sedang',
      low: 'Rendah',
      triggerScenario: 'Uji Deteksi:',
      incidentTable: 'Daftar Insiden & Peringatan Aktif',
      sourceAsset: 'Sumber & Aset Tujuan',
      vectorTactic: 'Vektor & Taktik MITRE',
      severity: 'Tingkat Risiko',
      status: 'Status',
      actions: 'Tindakan',
      blockIp: 'Blokir IP',
      resolve: 'Mitigasi',
      acknowledge: 'Konfirmasi',
      automationRulesTitle: 'Aturan Respon & Notifikasi Otomatis',
      addRuleBtn: 'Tambah Aturan',
      ruleNamePlaceholder: 'Nama aturan respon otomatis...',
      minSeverity: 'Severitas Minimum',
      ruleAction: 'Aksi Otomatis',
      saveRule: 'Simpan Aturan',
      startDrill: 'Simulasi Berkelanjutan',
      stopDrill: 'Hentikan Simulasi',
      drillRunning: 'Serangan Multi-Gelombang Aktif',
      wavesExecuted: 'gelombang tereksekusi',
      viewDetails: 'Lihat Ancaman',
    },
    logs: {
      title: 'Brankas Log Trafik Terenkripsi End-to-End',
      subtitle: 'Seluruh log paket disegel menggunakan AES-256-GCM dan rantai integritas hash SHA-256.',
      activeKey: 'ID Kunci Aktif',
      algorithm: 'Algoritma Enkripsi',
      verifyChain: 'Verifikasi Rantai Hash',
      rotateKey: 'Rotasi Kunci E2E',
      decryptAll: 'Dekripsi Payload',
      hidePlaintext: 'Sembunyikan Plaintext',
      chainVerifiedOk: 'Integritas rantai hash terverifikasi utuh',
      chainBroken: 'Ketidakcocokan integritas terdeteksi pada urutan',
      sequence: 'Urutan',
      timestamp: 'Waktu',
      endpoint: 'Sumber -> Port',
      ciphertextPreview: 'Ciphertext AES-256-GCM',
      integrityHash: 'Hash SHA-256',
      payloadStatus: 'Payload Terdekripsi',
      encryptedLabel: 'Terenkripsi (E2E)',
      decryptedLabel: 'Terverifikasi',
    },
    siem: {
      title: 'Integrasi SIEM & API Pihak Ketiga',
      subtitle: 'Sinkronisasi log ke Splunk, Elastic, QRadar, Sentinel serta kepatuhan standar industri.',
      connectorsTitle: 'Konektor SIEM Terhubung',
      testSync: 'Uji Sinkronisasi',
      payloadPreview: 'Pratinjau Payload Terakhir',
      apiKeysTitle: 'Kunci API Ingesti SIEM',
      keyLabelPlaceholder: 'Label kunci API baru (mis. Splunk Prod)...',
      createKeyBtn: 'Buat Kunci API',
      copyOnceWarning: 'Salin kunci rahasia sekarang. Kunci ini hanya ditampilkan satu kali:',
      revokeBtn: 'Cabut',
      thirdPartyTitle: 'Platform Pihak Ketiga & Notifikasi Tim',
      complianceTitle: 'Kepatuhan Standar Keamanan Industri',
      eventsSynced: 'Event Tersinkron',
    },
    reports: {
      title: 'Laporan Mingguan Otomatis & Skalabilitas Klaster',
      subtitle: 'Ringkasan audit eksekutif mingguan serta penskalaan worker otomatis untuk lonjakan data.',
      weeklyReportsTitle: 'Arsip Laporan Keamanan Mingguan',
      generateNow: 'Buat Laporan Sekarang',
      downloadCsv: 'Unduh CSV',
      downloadJson: 'Unduh JSON',
      scheduleTitle: 'Jadwal Pengiriman Otomatis',
      scheduleEnabled: 'Aktifkan Laporan Mingguan Otomatis',
      dayLabel: 'Hari Pengiriman',
      timeUtcLabel: 'Waktu (UTC)',
      recipientsLabel: 'Penerima Email Audit',
      saveSchedule: 'Simpan Jadwal',
      scalabilityTitle: 'Skalabilitas Horizontal & Kapasitas Lonjakan Data',
      autoScaleToggle: 'Auto-Scaling Worker Aktif',
      maxNodesLabel: 'Batas Maksimum Node',
      targetLoadLabel: 'Target Beban CPU (%)',
      stressTestStart: 'Uji Lonjakan Beban (100 Gbps)',
      stressTestStop: 'Hentikan Uji Lonjakan',
      activeNodes: 'Node Ingesti Aktif',
      kafkaBuffer: 'Buffer Antrean Stream',
      headroom: 'Kapasitas Maksimum',
    },
    mfa: {
      title: 'Keamanan Akun & Autentikasi Multifaktor',
      subtitle: 'Kelola kebijakan TOTP RFC 6238, kode pemulihan darurat, dan audit sesi aktif.',
      statusTitle: 'Status Proteksi MFA',
      mfaActiveLabel: 'MFA TOTP Aktif & Terverifikasi',
      totpStandard: 'Standar RFC 6238 (HMAC-SHA1 · 6 Digit · 30 Detik)',
      policyDecryption: 'Wajibkan sesi terverifikasi MFA untuk dekripsi log E2E',
      policyKeyRotation: 'Wajibkan sesi terverifikasi MFA untuk rotasi kunci kriptografi',
      backupCodesTitle: 'Kode Pemulihan Cadangan',
      backupRemaining: 'Sisa kode pemulihan aktif',
      regenerateBackupBtn: 'Buat Ulang Kode Pemulihan',
      sessionsTitle: 'Sesi Administrator Terautentikasi',
      sessionEmail: 'Akun',
      sessionRole: 'Peran',
      sessionVerified: 'Status MFA',
    },
    users: {
      title: 'Dasbor Kontrol & Pemantauan Akun Pengguna',
      subtitle: 'Pantau pendaftaran dari seluruh perangkat secara real-time, setujui akses, tangguhkan akun bermasalah, dan putus sesi aktif.',
      kpiTotal: 'Total Akun Terdaftar',
      kpiPending: 'Menunggu Persetujuan',
      kpiActive: 'Akun Aktif',
      kpiRestricted: 'Ditangguhkan / Diblokir',
      requireApprovalLabel: 'Wajib Persetujuan Admin untuk Pendaftar Baru',
      requireApprovalHint: 'Setiap akun dari perangkat lain otomatis masuk antrean Admin sebelum dapat login.',
      searchPlaceholder: 'Cari nama, email, IP perangkat, atau catatan masalah...',
      all: 'Semua',
      pending: 'Menunggu',
      active: 'Aktif',
      suspended: 'Ditangguhkan',
      blocked: 'Diblokir',
      userColumn: 'Pengguna & Departemen',
      deviceColumn: 'Perangkat & IP Pendaftaran',
      roleColumn: 'Peran Akses',
      statusColumn: 'Status & MFA',
      controlsColumn: 'Kontrol Admin',
      activateBtn: 'Aktifkan',
      suspendBtn: 'Tangguhkan',
      blockBtn: 'Blokir',
      resetMfaBtn: 'Reset MFA',
      revokeSessionsBtn: 'Putus Sesi',
      flagIssueBtn: 'Tandai Masalah',
      resolveIssueBtn: 'Selesaikan Masalah',
      issueNotePlaceholder: 'Catat alasan suspensi/masalah akun (opsional)...',
      saveIssueBtn: 'Simpan Catatan',
      cancelBtn: 'Batal',
      emptyState: 'Belum ada akun pengguna terdaftar yang cocok dengan filter ini.',
      auditTitle: 'Log Audit Kontrol Akun Admin',
      auditSubtitle: 'Rekam jejak seluruh pendaftaran lintas perangkat dan tindakan kontrol Admin.',
      mfaEnrolled: 'MFA Terdaftar',
      mfaPending: 'MFA Belum Enrol',
      activeSessions: 'sesi aktif',
      tabAccounts: 'Akun Pengguna',
      tabComplaints: 'Keluhan & Laporan Masuk',
      complaintsEmpty: 'Belum ada keluhan atau laporan masuk dari pengguna.',
      respondNotePlaceholder: 'Tulis balasan / tindakan penyelesaian untuk pengguna...',
      markInReviewBtn: 'Tinjau',
      markResolvedBtn: 'Selesaikan',
      sendReplyBtn: 'Simpan Balasan',
      handledByLabel: 'Ditangani oleh',
      viewComplaintsBtn: 'Lihat Keluhan',
    },
  },
  en: {
    brandName: 'SentinelGrid',
    nav: {
      overview: 'SOC Overview',
      threats: 'Threats & Response',
      logs: 'E2E Encrypted Logs',
      siem: 'SIEM & API Sync',
      reports: 'Reports & Scalability',
      mfa: 'MFA & Access',
      users: 'User Control',
      complaints: 'Complaints & Reports',
    },
    portal: {
      adminPortalBadge: 'Admin Portal (/admin)',
      userPortalBadge: 'User Portal (/user)',
      adminPortalTitle: 'Administrator Portal',
      userPortalTitle: 'User Portal',
      openUserPortal: 'Open User Portal (/user)',
      openAdminPortal: 'Open Admin Portal (/admin)',
      switchToUserLink: 'User Sign-In / Register → /user',
      switchToAdminLink: 'Admin Sign-In → /admin',
      separateSessionHint: '/admin and /user sessions stay isolated so signing into one never signs out the other.',
      userPortalWaitAdmin: 'Administrator workspace is not initialized yet. Activate the root Admin account at /admin first.',
      registerHintUserPortal: 'Team registration and user issue reporting take place via the User Portal link (/user).',
    },
    complaints: {
      title: 'Submit Issue Report or Complaint to Admin',
      subtitle: 'All reports submitted from this device route directly to the Admin dashboard in real time.',
      categoryLabel: 'Category',
      severityLabel: 'Urgency',
      subjectLabel: 'Subject',
      subjectPlaceholder: 'e.g. MFA access issue or suspicious traffic alert...',
      descriptionLabel: 'Detailed Description',
      descriptionPlaceholder: 'Describe the issue, affected workflow, or incident details...',
      submitBtn: 'Send Report to Admin',
      submittedBanner: 'Report delivered to the Administrator console in real time.',
      myHistoryTitle: 'Submitted Reports & Admin Responses',
      emptyHistory: 'You have not submitted any complaints or reports yet.',
      adminReplyLabel: 'Admin Response',
      statusOpen: 'Pending Review',
      statusInReview: 'Under Review',
      statusResolved: 'Resolved',
      catAccessMfa: 'Access / MFA Issue',
      catSecurityIncident: 'Security Anomaly / Threat',
      catPerformanceBug: 'System Performance / Bug',
      catPolicyRequest: 'Access / Policy Request',
      catOther: 'Other',
    },
    auth: {
      setupTitle: 'Initialize SOC Security Workspace',
      setupSubtitle: 'Claim the primary administrator account and enroll TOTP multi-factor authentication.',
      loginTitle: 'Sign In to SentinelGrid Console',
      loginSubtitle: 'Protected enterprise console with password and multi-factor authentication.',
      registerTitle: 'Register Team User Account',
      registerSubtitle: 'Registrations from any device are routed straight to the Admin Control Dashboard.',
      tabSignIn: 'Sign In',
      tabRegister: 'Register',
      mfaTitle: 'Multi-Factor Verification',
      mfaSubtitle: 'Enter the 6-digit code from your authenticator app or a backup recovery code.',
      fullNameLabel: 'Full Name',
      departmentLabel: 'Department / Team',
      deviceNameLabel: 'Device Name (Auto-Detected / Optional)',
      deviceNamePlaceholder: 'e.g. Samsung Galaxy S24 / Pixel 8 / Work Laptop',
      emailLabel: 'Administrator Email',
      accountEmailLabel: 'Account Email',
      passwordLabel: 'Password',
      createAdminBtn: 'Create Admin & Continue to MFA',
      signInBtn: 'Continue to MFA Verification',
      registerBtn: 'Submit Registration to Admin',
      registerSuccessTitle: 'Registration Sent to Administrator',
      registerSuccessDesc: 'Your account has been recorded centrally and queued in the Admin Control Dashboard. Sign in once activated by Admin.',
      backToSignIn: 'Back to Sign In',
      mfaCodeLabel: '6-Digit TOTP or Recovery Code',
      verifyMfaBtn: 'Verify & Enter Console',
      enrollSecretLabel: 'TOTP Enrollment Secret (Base32)',
      backupCodesLabel: 'Backup Recovery Codes (Save Securely)',
      generateHelperBtn: 'Fill TOTP Code from Enrollment Key',
      backToLogin: 'Back to Sign In',
      mfaProtectedNote: 'Sessions are secured with HMAC-SHA256 tokens and OTP / RFC 6238 TOTP.',
      adminOtpTitle: 'Admin Sign-In via Email OTP',
      adminOtpSubtitle: 'Enter your administrator email only. A 6-digit OTP replaces passwords for Admin access.',
      sendOtpBtn: 'Send OTP Code to Email',
      otpVerifyTitle: 'Enter Email OTP Code',
      otpVerifySubtitle: 'Enter the 6-digit verification code sent to your administrator email address.',
      otpCodeLabel: '6-Digit Email OTP Code',
      verifyOtpBtn: 'Verify OTP & Open Admin Console',
      resendOtpBtn: 'Resend OTP Code',
      changeAdminEmailBtn: 'Change Admin Email',
      otpPreviewTitle: 'Instant OTP Inbox Preview (No SMTP/Resend Key)',
      otpPreviewHint: 'RESEND_API_KEY is not configured yet. Use this server-issued OTP to sign in right away:',
      fillOtpHelperBtn: 'Fill OTP Code Automatically',
      otpSentEmailNotice: 'A 6-digit OTP has been sent to your email inbox (valid for 10 minutes).',
    },
    topbar: {
      simulateProbe: 'Simulate Probe',
      notifications: 'Security Alerts',
      markAllRead: 'Mark All Read',
      noNotifications: 'All security alerts have been reviewed.',
      lightMode: 'Light Mode',
      darkMode: 'Dark Mode',
      signOut: 'Sign Out',
      wsConnected: 'Live Stream Connected',
      wsReconnecting: 'Reconnecting...',
      simulatingLabel: 'Drill Active',
      viewerReadOnlyTip: 'Read-only access (Viewer)',
    },
    overview: {
      title: 'Real-Time Network Traffic & Threat Telemetry',
      subtitle: 'Live packet inspection, automated anomaly detection, and cluster capacity headroom.',
      kpiThroughput: 'Active Throughput',
      kpiThreats: 'Detected Threats',
      kpiEncryptedLogs: 'E2E Encrypted Logs',
      kpiClusterCapacity: 'Cluster Capacity',
      chartTitle: 'Live Network Throughput Stream',
      chartSubtitle: 'Real-time inbound/outbound bandwidth (Gbps) and dropped packet rate.',
      inbound: 'Inbound',
      outbound: 'Outbound',
      blockedPps: 'Dropped Packets',
      protocolMix: 'Protocol Breakdown',
      recentThreats: 'Recent Threat Detections',
      viewAllThreats: 'View All Threats',
      blockIp: 'Block IP',
      mitigate: 'Mitigate',
      automatedCount: 'Active Auto-Rules',
      globeTitle: 'Live Global Threat Globe',
      globeSubtitle: 'Drag to spin · Real-time attack vectors to Jakarta SOC Hub',
      pauseRotation: 'Pause Globe Rotation',
      resumeRotation: 'Resume Globe Rotation',
      resetView: 'Reset Globe View',
    },
    threats: {
      title: 'Threat Detection & Automated Response',
      subtitle: 'Inspect live cyber incidents, block malicious IPs, and configure automated team alerts.',
      searchPlaceholder: 'Filter by source IP, target asset, or signature ID...',
      all: 'All',
      critical: 'Critical',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
      triggerScenario: 'Test Probe:',
      incidentTable: 'Active Incidents & Security Alerts',
      sourceAsset: 'Source & Target Asset',
      vectorTactic: 'Vector & MITRE Tactic',
      severity: 'Severity',
      status: 'Status',
      actions: 'Actions',
      blockIp: 'Block IP',
      resolve: 'Mitigate',
      acknowledge: 'Acknowledge',
      automationRulesTitle: 'Automated Notification & Response Rules',
      addRuleBtn: 'Add Rule',
      ruleNamePlaceholder: 'Automation rule name...',
      minSeverity: 'Min Severity',
      ruleAction: 'Automated Action',
      saveRule: 'Save Rule',
      startDrill: 'Continuous Simulation',
      stopDrill: 'Stop Simulation',
      drillRunning: 'Multi-Wave Attack Drill Active',
      wavesExecuted: 'waves executed',
      viewDetails: 'View Threats',
    },
    logs: {
      title: 'End-to-End Encrypted Traffic Log Vault',
      subtitle: 'Every network log entry is sealed with AES-256-GCM and a tamper-evident SHA-256 hash chain.',
      activeKey: 'Active Key ID',
      algorithm: 'Cipher Suite',
      verifyChain: 'Verify Hash Chain',
      rotateKey: 'Rotate E2E Key',
      decryptAll: 'Decrypt Payloads',
      hidePlaintext: 'Hide Plaintext',
      chainVerifiedOk: 'Cryptographic hash chain verified intact',
      chainBroken: 'Integrity mismatch detected at sequence',
      sequence: 'Seq',
      timestamp: 'Timestamp',
      endpoint: 'Source -> Port',
      ciphertextPreview: 'AES-256-GCM Ciphertext',
      integrityHash: 'SHA-256 Chain Hash',
      payloadStatus: 'Decrypted Payload',
      encryptedLabel: 'Sealed (E2E)',
      decryptedLabel: 'Verified',
    },
    siem: {
      title: 'SIEM Connectors & Third-Party API Sync',
      subtitle: 'Stream events to Splunk, Elastic, QRadar, Sentinel and synchronize security tooling.',
      connectorsTitle: 'Configured SIEM Connectors',
      testSync: 'Test SIEM Sync',
      payloadPreview: 'Last Dispatched Payload',
      apiKeysTitle: 'SIEM Ingestion API Keys',
      keyLabelPlaceholder: 'New API key label (e.g. Splunk Prod)...',
      createKeyBtn: 'Create API Key',
      copyOnceWarning: 'Copy your secret API key now. It will not be shown again:',
      revokeBtn: 'Revoke',
      thirdPartyTitle: 'Third-Party Platforms & Team Notifications',
      complianceTitle: 'Industry Compliance & Audit Coverage',
      eventsSynced: 'Events Synced',
    },
    reports: {
      title: 'Automated Weekly Reports & Cluster Scalability',
      subtitle: 'Scheduled executive compliance digests and horizontal auto-scaling for traffic spikes.',
      weeklyReportsTitle: 'Weekly Executive Security Reports',
      generateNow: 'Generate Report Now',
      downloadCsv: 'Export CSV',
      downloadJson: 'Export JSON',
      scheduleTitle: 'Automated Weekly Digest Schedule',
      scheduleEnabled: 'Enable Automated Weekly Reports',
      dayLabel: 'Delivery Day',
      timeUtcLabel: 'Time (UTC)',
      recipientsLabel: 'Audit Recipients',
      saveSchedule: 'Save Schedule',
      scalabilityTitle: 'Horizontal Cluster Scaling & Surge Capacity',
      autoScaleToggle: 'Auto-Scale Workers Enabled',
      maxNodesLabel: 'Max Worker Nodes',
      targetLoadLabel: 'Target CPU Load (%)',
      stressTestStart: 'Simulate Load Spike (100 Gbps)',
      stressTestStop: 'Stop Spike Simulation',
      activeNodes: 'Active Ingest Nodes',
      kafkaBuffer: 'Stream Buffer Load',
      headroom: 'Cluster Headroom',
    },
    mfa: {
      title: 'Account Security & Multi-Factor Authentication',
      subtitle: 'Manage RFC 6238 TOTP policies, backup recovery codes, and active admin sessions.',
      statusTitle: 'MFA Enforcement Status',
      mfaActiveLabel: 'TOTP MFA Active & Verified',
      totpStandard: 'RFC 6238 Standard (HMAC-SHA1 · 6 Digits · 30s Window)',
      policyDecryption: 'Require MFA-verified session to decrypt E2E traffic logs',
      policyKeyRotation: 'Require MFA-verified session for cryptographic key rotation',
      backupCodesTitle: 'Backup Recovery Codes',
      backupRemaining: 'Active recovery codes remaining',
      regenerateBackupBtn: 'Regenerate Recovery Codes',
      sessionsTitle: 'Authenticated Administrator Sessions',
      sessionEmail: 'Account',
      sessionRole: 'Role',
      sessionVerified: 'MFA Status',
    },
    users: {
      title: 'Admin User Control & Registration Monitor',
      subtitle: 'Monitor registrations across all devices in real time, approve access, suspend troubled accounts, and terminate active sessions.',
      kpiTotal: 'Total Registered Users',
      kpiPending: 'Pending Approval',
      kpiActive: 'Active Users',
      kpiRestricted: 'Suspended / Blocked',
      requireApprovalLabel: 'Require Admin Approval for New Registrations',
      requireApprovalHint: 'Every account registered on another device enters the Admin approval queue before sign-in.',
      searchPlaceholder: 'Search name, email, device IP, or issue notes...',
      all: 'All',
      pending: 'Pending',
      active: 'Active',
      suspended: 'Suspended',
      blocked: 'Blocked',
      userColumn: 'User & Department',
      deviceColumn: 'Registered Device & IP',
      roleColumn: 'Role',
      statusColumn: 'Status & MFA',
      controlsColumn: 'Admin Controls',
      activateBtn: 'Activate',
      suspendBtn: 'Suspend',
      blockBtn: 'Block',
      resetMfaBtn: 'Reset MFA',
      revokeSessionsBtn: 'Revoke Sessions',
      flagIssueBtn: 'Flag Issue',
      resolveIssueBtn: 'Resolve Issue',
      issueNotePlaceholder: 'Record suspension or incident note...',
      saveIssueBtn: 'Save Note',
      cancelBtn: 'Cancel',
      emptyState: 'No registered user accounts match the current filter.',
      auditTitle: 'Admin Account Control Audit Trail',
      auditSubtitle: 'Immutable record of cross-device registrations and administrator control actions.',
      mfaEnrolled: 'MFA Enrolled',
      mfaPending: 'MFA Pending',
      activeSessions: 'active sessions',
      tabAccounts: 'User Accounts',
      tabComplaints: 'Incoming Complaints & Reports',
      complaintsEmpty: 'No user complaints or reports have been received yet.',
      respondNotePlaceholder: 'Write response or resolution note for user...',
      markInReviewBtn: 'Mark In Review',
      markResolvedBtn: 'Resolve',
      sendReplyBtn: 'Send Reply',
      handledByLabel: 'Handled by',
      viewComplaintsBtn: 'View Complaints',
    },
  },
  ja: {
    brandName: 'SentinelGrid',
    nav: {
      overview: 'SOC 概要',
      threats: '脅威検知と対応',
      logs: 'E2E 暗号化ログ',
      siem: 'SIEM・API 連携',
      reports: '週次レポート・拡張性',
      mfa: '多要素認証 (MFA)',
      users: 'ユーザー管理',
      complaints: '報告・問い合わせ',
    },
    portal: {
      adminPortalBadge: '管理者ポータル (/admin)',
      userPortalBadge: '利用者ポータル (/user)',
      adminPortalTitle: '管理者ポータル',
      userPortalTitle: '利用者ポータル',
      openUserPortal: '利用者ポータルを開く (/user)',
      openAdminPortal: '管理者ポータルを開く (/admin)',
      switchToUserLink: 'ユーザーログイン・登録 → /user',
      switchToAdminLink: '管理者ログイン → /admin',
      separateSessionHint: '/admin と /user のセッションは分離されており、同時にログインできます。',
      userPortalWaitAdmin: '管理者ワークスペースがまだ初期化されていません。先に /admin で管理者を作成してください。',
      registerHintUserPortal: 'チームユーザーの登録と報告は利用者ポータル (/user) から行います。',
    },
    complaints: {
      title: '管理者へ報告・問題を送信',
      subtitle: 'この端末から送信した報告・不具合連絡はリアルタイムで管理者アカウントへ届きます。',
      categoryLabel: 'カテゴリ',
      severityLabel: '重要度',
      subjectLabel: '件名',
      subjectPlaceholder: '例: MFA認証の不具合や不審なアクセスについて...',
      descriptionLabel: '詳細説明',
      descriptionPlaceholder: '発生した問題や状況を詳しく記載してください...',
      submitBtn: '管理者に送信',
      submittedBanner: '報告が管理者ダッシュボードへリアルタイム送信されました。',
      myHistoryTitle: '送信履歴・管理者からの返信',
      emptyHistory: '送信した報告はまだありません。',
      adminReplyLabel: '管理者返信',
      statusOpen: '対応待ち',
      statusInReview: '確認中',
      statusResolved: '解決済み',
      catAccessMfa: 'アクセス / MFA の問題',
      catSecurityIncident: 'セキュリティ異常・脅威',
      catPerformanceBug: 'パフォーマンス / バグ',
      catPolicyRequest: '権限・ポリシー申請',
      catOther: 'その他',
    },
    auth: {
      setupTitle: 'SOC セキュリティワークスペースの初期化',
      setupSubtitle: '管理者アカウントを作成し、TOTP 多要素認証を設定してください。',
      loginTitle: 'SentinelGrid コンソールへサインイン',
      loginSubtitle: 'パスワードと多要素認証で保護されたエンタープライズ SOC です。',
      registerTitle: '新規ユーザーアカウント登録',
      registerSubtitle: '別端末からの登録情報もリアルタイムで管理者コンソールへ送信されます。',
      tabSignIn: 'サインイン',
      tabRegister: '新規登録',
      mfaTitle: '多要素認証 (MFA) 確認',
      mfaSubtitle: '認証アプリの 6 桁コードまたはリカバリーコードを入力してください。',
      fullNameLabel: '氏名',
      departmentLabel: '部署 / チーム',
      deviceNameLabel: '端末名（自動検出・任意編集）',
      deviceNamePlaceholder: '例: Samsung Galaxy S24 / Pixel 8 / 業務PC',
      emailLabel: '管理者メールアドレス',
      accountEmailLabel: 'メールアドレス',
      passwordLabel: 'パスワード',
      createAdminBtn: '管理者を作成して MFA へ進む',
      signInBtn: 'MFA 認証へ進む',
      registerBtn: '登録申請を管理者へ送信',
      registerSuccessTitle: '管理者へ登録申請を送信しました',
      registerSuccessDesc: 'アカウントは中央サーバーに記録され、管理者ダッシュボードに通知されました。承認後にログインできます。',
      backToSignIn: 'サインインに戻る',
      mfaCodeLabel: '6 桁 TOTP / リカバリーコード',
      verifyMfaBtn: '認証してコンソールを開く',
      enrollSecretLabel: 'TOTP シークレットキー (Base32)',
      backupCodesLabel: 'バックアップコード（安全に保管）',
      generateHelperBtn: '登録キーから TOTP コードを入力',
      backToLogin: 'ログインに戻る',
      mfaProtectedNote: 'セッションは HMAC-SHA256 とメール OTP / RFC 6238 TOTP で保護されています。',
      adminOtpTitle: 'メール OTP による管理者ログイン',
      adminOtpSubtitle: 'パスワードの代わりに管理者メールアドレスへ送信される 6 桁の OTP で認証します。',
      sendOtpBtn: 'メールへ OTP コードを送信',
      otpVerifyTitle: 'メール OTP コードを入力',
      otpVerifySubtitle: '管理者メールに送信された 6 桁の確認コードを入力してください。',
      otpCodeLabel: '6 桁メール OTP コード',
      verifyOtpBtn: 'OTP を確認して管理コンソールへ',
      resendOtpBtn: 'OTP を再送信',
      changeAdminEmailBtn: 'メールアドレスを変更',
      otpPreviewTitle: 'OTP 受信プレビュー（SMTP/Resend 未設定）',
      otpPreviewHint: 'RESEND_API_KEY 未設定のため、発行された OTP を表示しています:',
      fillOtpHelperBtn: 'OTP コードを自動入力',
      otpSentEmailNotice: '6 桁の OTP コードをメールに送信しました（10 分間有効）。',
    },
    topbar: {
      simulateProbe: '脅威シミュレーション',
      notifications: 'セキュリティ通知',
      markAllRead: 'すべて既読',
      noNotifications: '未読のセキュリティ通知はありません。',
      lightMode: 'ライトモード',
      darkMode: 'ダークモード',
      signOut: 'ログアウト',
      wsConnected: 'リアルタイム接続中',
      wsReconnecting: '再接続中...',
      simulatingLabel: '演習実行中',
      viewerReadOnlyTip: '閲覧専用権限 (Viewer)',
    },
    overview: {
      title: 'リアルタイムネットワーク監視と脅威分析',
      subtitle: 'ライブパケット監視、自動異常検知、およびクラスター拡張余力の統合ビュー。',
      kpiThroughput: '稼働スループット',
      kpiThreats: '検知された脅威',
      kpiEncryptedLogs: 'E2E 暗号化ログ',
      kpiClusterCapacity: 'クラスター容量',
      chartTitle: 'リアルタイム帯域ストリーム',
      chartSubtitle: '受信・送信スループット (Gbps) およびブロック済みパケット数。',
      inbound: '受信 (Inbound)',
      outbound: '送信 (Outbound)',
      blockedPps: 'ブロックパケット',
      protocolMix: 'プロトコル内訳',
      recentThreats: '最新の脅威検知',
      viewAllThreats: 'すべて表示',
      blockIp: 'IP ブロック',
      mitigate: '緩和対応',
      automatedCount: '有効な自動ルール',
      globeTitle: 'リアルタイム脅威地球儀',
      globeSubtitle: 'ドラッグで回転 · ジャカルタ SOC へのリアルタイム攻撃経路',
      pauseRotation: '地球儀の回転を一時停止',
      resumeRotation: '地球儀を回転',
      resetView: '表示をリセット',
    },
    threats: {
      title: '脅威検知と自動インシデント対応',
      subtitle: 'サイバー攻撃のリアルタイム分析、IP 遮断、自動通知ルールの管理。',
      searchPlaceholder: '送信元 IP、対象資産、シグネチャ ID で検索...',
      all: 'すべて',
      critical: '緊急',
      high: '高',
      medium: '中',
      low: '低',
      triggerScenario: 'テスト検知:',
      incidentTable: 'アクティブなインシデント一覧',
      sourceAsset: '送信元・対象資産',
      vectorTactic: '攻撃ベクター・MITRE 戦術',
      severity: '深刻度',
      status: 'ステータス',
      actions: '操作',
      blockIp: 'IP 遮断',
      resolve: '緩和',
      acknowledge: '確認済みにする',
      automationRulesTitle: '自動通知・防御ルール',
      addRuleBtn: 'ルール追加',
      ruleNamePlaceholder: '自動対応ルール名...',
      minSeverity: '最小深刻度',
      ruleAction: '実行アクション',
      saveRule: 'ルールを保存',
      startDrill: '連続攻撃シミュレーション',
      stopDrill: 'シミュレーション停止',
      drillRunning: '連続攻撃演習を実行中',
      wavesExecuted: '回の攻撃波を実行',
      viewDetails: '脅威一覧を見る',
    },
    logs: {
      title: 'エンドツーエンド暗号化ログ保管庫',
      subtitle: 'すべての通信ログは AES-256-GCM と改ざん検知用 SHA-256 チェーンで保護されます。',
      activeKey: '有効キー ID',
      algorithm: '暗号スイート',
      verifyChain: 'チェーン整合性検証',
      rotateKey: 'E2E 鍵ローテーション',
      decryptAll: 'ペイロード復号',
      hidePlaintext: '平文を隠す',
      chainVerifiedOk: 'SHA-256 ハッシュチェーンの整合性が確認されました',
      chainBroken: '整合性エラーが検出されました（シーケンス番号）',
      sequence: '連番',
      timestamp: 'タイムスタンプ',
      endpoint: '送信元 -> ポート',
      ciphertextPreview: 'AES-256-GCM 暗号文',
      integrityHash: 'SHA-256 ハッシュ',
      payloadStatus: '復号データ',
      encryptedLabel: '暗号化済 (E2E)',
      decryptedLabel: '検証済',
    },
    siem: {
      title: 'SIEM・サードパーティ API 連携',
      subtitle: 'Splunk、Elastic、QRadar、Sentinel へのログ連携と業界基準コンプライアンス。',
      connectorsTitle: 'SIEM コネクタ設定',
      testSync: '同期テスト',
      payloadPreview: '最新送信ペイロード',
      apiKeysTitle: 'SIEM 取り込み用 API キー',
      keyLabelPlaceholder: '新しい API キー名...',
      createKeyBtn: 'API キー発行',
      copyOnceWarning: 'シークレットキーは一度しか表示されません。今すぐコピーしてください:',
      revokeBtn: '失効',
      thirdPartyTitle: '外部連携・チーム通知チャネル',
      complianceTitle: '業界セキュリティ基準コンプライアンス',
      eventsSynced: '同期済みイベント',
    },
    reports: {
      title: '自動週次レポートと高スケーラビリティ管理',
      subtitle: '経営層向け週次セキュリティ要約とデータ急増に対応する水平オートスケール。',
      weeklyReportsTitle: '週次セキュリティレポート履歴',
      generateNow: '今すぐレポート生成',
      downloadCsv: 'CSV 出力',
      downloadJson: 'JSON 出力',
      scheduleTitle: '自動配信スケジュール',
      scheduleEnabled: '週次自動レポートを有効にする',
      dayLabel: '配信曜日',
      timeUtcLabel: '配信時刻 (UTC)',
      recipientsLabel: '送信先メールアドレス',
      saveSchedule: 'スケジュール保存',
      scalabilityTitle: 'クラスター自動拡張と負荷テスト',
      autoScaleToggle: 'ワーカー自動拡張を有効化',
      maxNodesLabel: '最大ノード数',
      targetLoadLabel: '目標 CPU 負荷 (%)',
      stressTestStart: '高負荷テスト開始 (100 Gbps)',
      stressTestStop: '高負荷テスト停止',
      activeNodes: '稼働ノード数',
      kafkaBuffer: 'ストリームバッファ負荷',
      headroom: '最大処理容量',
    },
    mfa: {
      title: 'アカウント保護と多要素認証 (MFA)',
      subtitle: 'RFC 6238 TOTP ポリシー、バックアップコード、およびアクティブセッション管理。',
      statusTitle: 'MFA 保護ステータス',
      mfaActiveLabel: 'TOTP MFA 有効・検証済み',
      totpStandard: 'RFC 6238 準拠 (HMAC-SHA1 · 6 桁 · 30 秒周期)',
      policyDecryption: 'E2E ログ復号時に MFA 検証済みセッションを必須化',
      policyKeyRotation: '暗号鍵ローテーション時に MFA 検証済みセッションを必須化',
      backupCodesTitle: 'バックアップリカバリーコード',
      backupRemaining: '残りの有効コード数',
      regenerateBackupBtn: 'コードを再生成',
      sessionsTitle: '認証済み管理者セッション',
      sessionEmail: 'アカウント',
      sessionRole: '役割',
      sessionVerified: 'MFA 状態',
    },
    users: {
      title: '管理者ユーザー監視・アクセス制御',
      subtitle: '他端末からの新規登録をリアルタイムで監視し、問題のあるアカウントを停止・遮断・セッション強制終了します。',
      kpiTotal: '登録アカウント総数',
      kpiPending: '承認待ち',
      kpiActive: '有効アカウント',
      kpiRestricted: '停止 / ブロック済み',
      requireApprovalLabel: '新規登録に管理者承認を必須にする',
      requireApprovalHint: '別端末からの新規登録は管理者が有効化するまで待機状態になります。',
      searchPlaceholder: '氏名、メール、端末IP、問題メモで検索...',
      all: 'すべて',
      pending: '承認待ち',
      active: '有効',
      suspended: '一時停止',
      blocked: 'ブロック',
      userColumn: 'ユーザー・部署',
      deviceColumn: '登録端末・IP',
      roleColumn: '権限ロール',
      statusColumn: '状態・MFA',
      controlsColumn: '管理者コントロール',
      activateBtn: '有効化',
      suspendBtn: '一時停止',
      blockBtn: 'ブロック',
      resetMfaBtn: 'MFA リセット',
      revokeSessionsBtn: 'セッション切断',
      flagIssueBtn: '問題を記録',
      resolveIssueBtn: '問題解消',
      issueNotePlaceholder: '停止理由またはインシデントメモを入力...',
      saveIssueBtn: '保存',
      cancelBtn: 'キャンセル',
      emptyState: '条件に一致する登録ユーザーはありません。',
      auditTitle: '管理者ユーザー制御監査ログ',
      auditSubtitle: '全端末からの登録履歴と管理者操作の不変監査レコード。',
      mfaEnrolled: 'MFA 登録済',
      mfaPending: 'MFA 未登録',
      activeSessions: '接続中セッション',
      tabAccounts: '登録アカウント',
      tabComplaints: 'ユーザーからの報告・相談',
      complaintsEmpty: 'ユーザーからの報告はまだありません。',
      respondNotePlaceholder: 'ユーザーへの返信・対応メモを入力...',
      markInReviewBtn: '確認中にする',
      markResolvedBtn: '解決済みにする',
      sendReplyBtn: '返信を保存',
      handledByLabel: '担当者',
      viewComplaintsBtn: '報告を確認',
    },
  },
  de: {
    brandName: 'SentinelGrid',
    nav: {
      overview: 'SOC Übersicht',
      threats: 'Bedrohungen & Abwehr',
      logs: 'E2E-Verschlüsselte Logs',
      siem: 'SIEM & API-Sync',
      reports: 'Berichte & Skalierung',
      mfa: 'MFA & Zugriff',
      users: 'Benutzerkontrolle',
      complaints: 'Meldungen & Beschwerden',
    },
    portal: {
      adminPortalBadge: 'Admin-Portal (/admin)',
      userPortalBadge: 'Benutzer-Portal (/user)',
      adminPortalTitle: 'Administrator-Portal',
      userPortalTitle: 'Benutzer-Portal',
      openUserPortal: 'Benutzer-Portal öffnen (/user)',
      openAdminPortal: 'Admin-Portal öffnen (/admin)',
      switchToUserLink: 'Benutzer-Login / Registrierung → /user',
      switchToAdminLink: 'Admin-Login → /admin',
      separateSessionHint: '/admin- und /user-Sitzungen sind getrennt, damit Sie nicht abgemeldet werden.',
      userPortalWaitAdmin: 'Der Admin-Arbeitsbereich wurde noch nicht eingerichtet. Aktivieren Sie zuerst den Admin unter /admin.',
      registerHintUserPortal: 'Benutzerregistrierung und Störungsmeldungen erfolgen über das Benutzer-Portal (/user).',
    },
    complaints: {
      title: 'Beschwerde oder Vorfall an Admin melden',
      subtitle: 'Jede Meldung von diesem Gerät geht in Echtzeit direkt beim Administrator-Konto ein.',
      categoryLabel: 'Kategorie',
      severityLabel: 'Dringlichkeit',
      subjectLabel: 'Betreff',
      subjectPlaceholder: 'z. B. MFA-Anmeldeproblem oder verdächtige Aktivität...',
      descriptionLabel: 'Beschreibung',
      descriptionPlaceholder: 'Beschreiben Sie das Problem oder den Sicherheitsvorfall...',
      submitBtn: 'Meldung an Admin senden',
      submittedBanner: 'Meldung wurde in Echtzeit an das Admin-Dashboard übermittelt.',
      myHistoryTitle: 'Eigene Meldungen & Admin-Antworten',
      emptyHistory: 'Noch keine Meldungen eingereicht.',
      adminReplyLabel: 'Admin-Antwort',
      statusOpen: 'Offen',
      statusInReview: 'In Prüfung',
      statusResolved: 'Gelöst',
      catAccessMfa: 'Zugriff / MFA',
      catSecurityIncident: 'Sicherheitsvorfall',
      catPerformanceBug: 'Systemfehler / Leistung',
      catPolicyRequest: 'Richtlinienanfrage',
      catOther: 'Sonstiges',
    },
    auth: {
      setupTitle: 'SOC-Sicherheitsbereich einrichten',
      setupSubtitle: 'Erstellen Sie das erste Administratorkonto und aktivieren Sie TOTP-MFA.',
      loginTitle: 'Anmeldung bei SentinelGrid',
      loginSubtitle: 'Geschützte Unternehmenskonsole mit Passwort und Multi-Faktor-Authentifizierung.',
      registerTitle: 'Benutzerkonto registrieren',
      registerSubtitle: 'Registrierungen von anderen Geräten erscheinen direkt im Admin-Kontroll-Dashboard.',
      tabSignIn: 'Anmelden',
      tabRegister: 'Registrieren',
      mfaTitle: 'Multi-Faktor-Verifizierung',
      mfaSubtitle: 'Geben Sie den 6-stelligen TOTP-Code oder einen Wiederherstellungscode ein.',
      fullNameLabel: 'Vollständiger Name',
      departmentLabel: 'Abteilung / Team',
      deviceNameLabel: 'Gerätename (Automatisch erkannt / Optional)',
      deviceNamePlaceholder: 'z. B. Samsung Galaxy S24 / Pixel 8 / Arbeits-Laptop',
      emailLabel: 'Administrator-E-Mail',
      accountEmailLabel: 'Konto-E-Mail',
      passwordLabel: 'Passwort',
      createAdminBtn: 'Admin erstellen & zu MFA',
      signInBtn: 'Weiter zur MFA-Prüfung',
      registerBtn: 'Registrierung an Admin senden',
      registerSuccessTitle: 'Registrierung an Admin gesendet',
      registerSuccessDesc: 'Ihr Konto wurde zentral gespeichert und dem Admin-Dashboard gemeldet. Anmeldung nach Admin-Freigabe.',
      backToSignIn: 'Zurück zur Anmeldung',
      mfaCodeLabel: '6-stelliger TOTP- oder Backup-Code',
      verifyMfaBtn: 'Verifizieren & Konsole öffnen',
      enrollSecretLabel: 'TOTP-Einrichtungsschlüssel (Base32)',
      backupCodesLabel: 'Backup-Wiederherstellungscodes',
      generateHelperBtn: 'TOTP-Code aus Schlüssel ausfüllen',
      backToLogin: 'Zurück zum Login',
      mfaProtectedNote: 'Sitzungen sind mit HMAC-SHA256 und E-Mail-OTP / RFC 6238 TOTP geschützt.',
      adminOtpTitle: 'Admin-Anmeldung per E-Mail-OTP',
      adminOtpSubtitle: 'Geben Sie nur Ihre Admin-E-Mail ein. Ein 6-stelliger E-Mail-OTP ersetzt das Passwort.',
      sendOtpBtn: 'OTP-Code an E-Mail senden',
      otpVerifyTitle: 'E-Mail-OTP-Code eingeben',
      otpVerifySubtitle: 'Geben Sie den 6-stelligen Bestätigungscode aus Ihrem Admin-Postfach ein.',
      otpCodeLabel: '6-stelliger E-Mail-OTP',
      verifyOtpBtn: 'OTP bestätigen & Admin öffnen',
      resendOtpBtn: 'OTP erneut senden',
      changeAdminEmailBtn: 'Admin-E-Mail ändern',
      otpPreviewTitle: 'OTP-Postfachvorschau (ohne SMTP/Resend)',
      otpPreviewHint: 'RESEND_API_KEY ist nicht gesetzt. Nutzen Sie diesen vom Server erzeugten OTP:',
      fillOtpHelperBtn: 'OTP-Code automatisch einfügen',
      otpSentEmailNotice: 'Ein 6-stelliger OTP wurde an Ihre E-Mail gesendet (10 Minuten gültig).',
    },
    topbar: {
      simulateProbe: 'Angriff simulieren',
      notifications: 'Sicherheitsmeldungen',
      markAllRead: 'Alle gelesen',
      noNotifications: 'Keine ungelesenen Sicherheitsmeldungen.',
      lightMode: 'Heller Modus',
      darkMode: 'Dunkler Modus',
      signOut: 'Abmelden',
      wsConnected: 'Live-Stream aktiv',
      wsReconnecting: 'Verbindung wird hergestellt...',
      simulatingLabel: 'Übung aktiv',
      viewerReadOnlyTip: 'Nur-Lese-Zugriff (Viewer)',
    },
    overview: {
      title: 'Echtzeit-Netzwerkverkehr & Bedrohungstelemetrie',
      subtitle: 'Live-Paketanalyse, automatische Anomalieerkennung und Cluster-Kapazität.',
      kpiThroughput: 'Aktiver Durchsatz',
      kpiThreats: 'Erkannte Bedrohungen',
      kpiEncryptedLogs: 'E2E-Verschlüsselte Logs',
      kpiClusterCapacity: 'Cluster-Kapazität',
      chartTitle: 'Live-Netzwerkdurchsatz',
      chartSubtitle: 'Echtzeit-Datenrate ein-/ausgehend (Gbps) und blockierte Pakete.',
      inbound: 'Eingehend',
      outbound: 'Ausgehend',
      blockedPps: 'Blockierte Pakete',
      protocolMix: 'Protokollverteilung',
      recentThreats: 'Aktuelle Bedrohungen',
      viewAllThreats: 'Alle anzeigen',
      blockIp: 'IP sperren',
      mitigate: 'Eindämmen',
      automatedCount: 'Aktive Auto-Regeln',
      globeTitle: 'Live-Bedrohungsglobus',
      globeSubtitle: 'Ziehen zum Drehen · Echtzeit-Angriffsvektoren zum Jakarta SOC',
      pauseRotation: 'Globus-Rotation pausieren',
      resumeRotation: 'Globus drehen',
      resetView: 'Ansicht zurücksetzen',
    },
    threats: {
      title: 'Bedrohungserkennung & Automatische Abwehr',
      subtitle: 'Echtzeit-Vorfallsanalyse, IP-Sperrung und automatisierte Team-Benachrichtigungen.',
      searchPlaceholder: 'Nach Quell-IP, Zielsystem oder Signatur-ID suchen...',
      all: 'Alle',
      critical: 'Kritisch',
      high: 'Hoch',
      medium: 'Mittel',
      low: 'Niedrig',
      triggerScenario: 'Test-Erkennung:',
      incidentTable: 'Aktive Sicherheitsvorfälle',
      sourceAsset: 'Quelle & Zielsystem',
      vectorTactic: 'Vektor & MITRE-Taktik',
      severity: 'Schweregrad',
      status: 'Status',
      actions: 'Aktionen',
      blockIp: 'IP sperren',
      resolve: 'Eindämmen',
      acknowledge: 'Bestätigen',
      automationRulesTitle: 'Automatisierte Reaktionsregeln',
      addRuleBtn: 'Regel hinzufügen',
      ruleNamePlaceholder: 'Regelname...',
      minSeverity: 'Mindestschweregrad',
      ruleAction: 'Automatische Aktion',
      saveRule: 'Regel speichern',
      startDrill: 'Dauer-Simulation',
      stopDrill: 'Simulation stoppen',
      drillRunning: 'Mehrstufige Angriffsübung aktiv',
      wavesExecuted: 'Wellen ausgeführt',
      viewDetails: 'Bedrohungen öffnen',
    },
    logs: {
      title: 'Ende-zu-Ende-verschlüsselter Log-Tresor',
      subtitle: 'Alle Verkehrsprotokolle sind mit AES-256-GCM und SHA-256-Hash-Kette gesichert.',
      activeKey: 'Aktive Schlüssel-ID',
      algorithm: 'Verschlüsselung',
      verifyChain: 'Hash-Kette prüfen',
      rotateKey: 'E2E-Schlüssel rotieren',
      decryptAll: 'Nutzdaten entschlüsseln',
      hidePlaintext: 'Klartext ausblenden',
      chainVerifiedOk: 'Kryptografische Hash-Kette vollständig verifiziert',
      chainBroken: 'Integritätsfehler erkannt bei Sequenz',
      sequence: 'Seq',
      timestamp: 'Zeitstempel',
      endpoint: 'Quelle -> Port',
      ciphertextPreview: 'AES-256-GCM Geheimtext',
      integrityHash: 'SHA-256 Ketten-Hash',
      payloadStatus: 'Entschlüsselte Daten',
      encryptedLabel: 'Versiegelt (E2E)',
      decryptedLabel: 'Verifiziert',
    },
    siem: {
      title: 'SIEM-Konnektoren & Drittanbieter-APIs',
      subtitle: 'Synchronisation mit Splunk, Elastic, QRadar, Sentinel und Compliance-Standards.',
      connectorsTitle: 'Konfigurierte SIEM-Konnektoren',
      testSync: 'Sync testen',
      payloadPreview: 'Letzte gesendete Nutzdaten',
      apiKeysTitle: 'SIEM-Ingestion-API-Schlüssel',
      keyLabelPlaceholder: 'Neuer Schlüsselname...',
      createKeyBtn: 'API-Schlüssel erstellen',
      copyOnceWarning: 'Kopieren Sie den geheimen Schlüssel jetzt. Er wird nur einmal angezeigt:',
      revokeBtn: 'Widerrufen',
      thirdPartyTitle: 'Drittanbieter-Plattformen & Benachrichtigungen',
      complianceTitle: 'Industriestandard-Compliance',
      eventsSynced: 'Synchronisierte Ereignisse',
    },
    reports: {
      title: 'Wöchentliche Berichte & Cluster-Skalierbarkeit',
      subtitle: 'Automatisierte Compliance-Berichte und horizontale Autoskalierung bei Lastspitzen.',
      weeklyReportsTitle: 'Wöchentliche Sicherheitsberichte',
      generateNow: 'Bericht jetzt erstellen',
      downloadCsv: 'CSV laden',
      downloadJson: 'JSON laden',
      scheduleTitle: 'Automatischer Zeitplan',
      scheduleEnabled: 'Wöchentliche Berichte aktivieren',
      dayLabel: 'Versandtag',
      timeUtcLabel: 'Uhrzeit (UTC)',
      recipientsLabel: 'Audit-Empfänger',
      saveSchedule: 'Zeitplan speichern',
      scalabilityTitle: 'Horizontale Cluster-Skalierung',
      autoScaleToggle: 'Auto-Scaling aktiviert',
      maxNodesLabel: 'Max. Worker-Knoten',
      targetLoadLabel: 'Ziel-CPU-Last (%)',
      stressTestStart: 'Lastspitze testen (100 Gbps)',
      stressTestStop: 'Lasttest beenden',
      activeNodes: 'Aktive Knoten',
      kafkaBuffer: 'Stream-Pufferlast',
      headroom: 'Gesamtkapazität',
    },
    mfa: {
      title: 'Kontosicherheit & Multi-Faktor-Authentifizierung',
      subtitle: 'Verwaltung von RFC 6238 TOTP-Richtlinien, Backup-Codes und aktiven Sitzungen.',
      statusTitle: 'MFA-Schutzstatus',
      mfaActiveLabel: 'TOTP-MFA aktiv & verifiziert',
      totpStandard: 'RFC 6238 Standard (HMAC-SHA1 · 6 Ziffern · 30s)',
      policyDecryption: 'MFA-Sitzung für E2E-Log-Entschlüsselung erzwingen',
      policyKeyRotation: 'MFA-Sitzung für Schlüsselrotation erzwingen',
      backupCodesTitle: 'Backup-Wiederherstellungscodes',
      backupRemaining: 'Verbleibende Backup-Codes',
      regenerateBackupBtn: 'Codes neu generieren',
      sessionsTitle: 'Authentifizierte Admin-Sitzungen',
      sessionEmail: 'Konto',
      sessionRole: 'Rolle',
      sessionVerified: 'MFA-Status',
    },
    users: {
      title: 'Admin-Benutzerkontrolle & Registrierungsmonitor',
      subtitle: 'Überwachen Sie Registrierungen aller Geräte in Echtzeit, genehmigen Sie Zugriffe und sperren Sie problematische Konten.',
      kpiTotal: 'Registrierte Konten',
      kpiPending: 'Freigabe ausstehend',
      kpiActive: 'Aktive Konten',
      kpiRestricted: 'Gesperrt / Ausgesetzt',
      requireApprovalLabel: 'Admin-Freigabe für neue Registrierungen erzwingen',
      requireApprovalHint: 'Jedes neu registrierte Konto von einem anderen Gerät landet zuerst in der Admin-Warteschlange.',
      searchPlaceholder: 'Name, E-Mail, Geräte-IP oder Problemnotiz suchen...',
      all: 'Alle',
      pending: 'Ausstehend',
      active: 'Aktiv',
      suspended: 'Ausgesetzt',
      blocked: 'Blockiert',
      userColumn: 'Benutzer & Abteilung',
      deviceColumn: 'Gerät & IP',
      roleColumn: 'Rolle',
      statusColumn: 'Status & MFA',
      controlsColumn: 'Admin-Aktionen',
      activateBtn: 'Aktivieren',
      suspendBtn: 'Aussetzen',
      blockBtn: 'Blockieren',
      resetMfaBtn: 'MFA zurücksetzen',
      revokeSessionsBtn: 'Sitzungen beenden',
      flagIssueBtn: 'Problem melden',
      resolveIssueBtn: 'Problem lösen',
      issueNotePlaceholder: 'Grund oder Vorfallsnotiz eingeben...',
      saveIssueBtn: 'Speichern',
      cancelBtn: 'Abbrechen',
      emptyState: 'Keine registrierten Benutzerkonten entsprechen dem Filter.',
      auditTitle: 'Admin-Kontrollprotokoll',
      auditSubtitle: 'Unveränderliche Historie aller Geräteregistrierungen und Admin-Eingriffe.',
      mfaEnrolled: 'MFA aktiv',
      mfaPending: 'MFA ausstehend',
      activeSessions: 'aktive Sitzungen',
      tabAccounts: 'Benutzerkonten',
      tabComplaints: 'Eingegangene Meldungen',
      complaintsEmpty: 'Noch keine Benutzermeldungen eingegangen.',
      respondNotePlaceholder: 'Antwort oder Lösungsnotiz eingeben...',
      markInReviewBtn: 'In Prüfung',
      markResolvedBtn: 'Lösen',
      sendReplyBtn: 'Antwort senden',
      handledByLabel: 'Bearbeitet von',
      viewComplaintsBtn: 'Meldungen ansehen',
    },
  },
};
