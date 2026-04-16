/* ============================================
   PhishGuard — Landing Page JavaScript
   Particles, scroll animations, counters
   ============================================ */

(function () {
    'use strict';

    // --- Particle Background ---
    const canvas = document.getElementById('particle-canvas');
    const ctx = canvas.getContext('2d');
    let particles = [];
    let animationId;

    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }

    function createParticles() {
        particles = [];
        const count = Math.min(60, Math.floor(window.innerWidth / 20));
        for (let i = 0; i < count; i++) {
            particles.push({
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height,
                radius: Math.random() * 1.5 + 0.5,
                vx: (Math.random() - 0.5) * 0.3,
                vy: (Math.random() - 0.5) * 0.3,
                opacity: Math.random() * 0.4 + 0.1,
            });
        }
    }

    function drawParticles() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        particles.forEach((p, i) => {
            // Move
            p.x += p.vx;
            p.y += p.vy;

            // Wrap
            if (p.x < 0) p.x = canvas.width;
            if (p.x > canvas.width) p.x = 0;
            if (p.y < 0) p.y = canvas.height;
            if (p.y > canvas.height) p.y = 0;

            // Draw particle
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(102, 126, 234, ${p.opacity})`;
            ctx.fill();

            // Draw connections
            for (let j = i + 1; j < particles.length; j++) {
                const p2 = particles[j];
                const dist = Math.hypot(p.x - p2.x, p.y - p2.y);
                if (dist < 150) {
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(p2.x, p2.y);
                    ctx.strokeStyle = `rgba(102, 126, 234, ${0.06 * (1 - dist / 150)})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        });

        animationId = requestAnimationFrame(drawParticles);
    }

    resizeCanvas();
    createParticles();
    drawParticles();

    window.addEventListener('resize', () => {
        resizeCanvas();
        createParticles();
    });

    // --- Navbar Scroll Effect ---
    const navbar = document.getElementById('navbar');

    function handleScroll() {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    }

    window.addEventListener('scroll', handleScroll, { passive: true });

    // --- Mobile Menu Toggle ---
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const navLinks = document.querySelector('.nav-links');

    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', () => {
            navLinks.classList.toggle('active');
        });

        // Close menu on link click
        navLinks.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                navLinks.classList.remove('active');
            });
        });
    }

    // --- Scroll-Triggered Animations (custom AOS) ---
    const animatedElements = document.querySelectorAll('[data-aos]');

    function checkAnimations() {
        const windowHeight = window.innerHeight;
        const triggerPoint = windowHeight * 0.85;

        animatedElements.forEach(el => {
            const rect = el.getBoundingClientRect();
            const delay = parseInt(el.getAttribute('data-aos-delay')) || 0;

            if (rect.top < triggerPoint) {
                setTimeout(() => {
                    el.classList.add('aos-animate');
                }, delay);
            }
        });
    }

    window.addEventListener('scroll', checkAnimations, { passive: true });
    window.addEventListener('load', checkAnimations);

    // --- Counter Animation ---
    const statValues = document.querySelectorAll('.stat-value');
    let countersStarted = false;

    function animateCounters() {
        if (countersStarted) return;

        const statsSection = document.getElementById('stats');
        if (!statsSection) return;

        const rect = statsSection.getBoundingClientRect();
        if (rect.top > window.innerHeight * 0.8) return;

        countersStarted = true;

        statValues.forEach(el => {
            const target = parseInt(el.getAttribute('data-target'));
            const suffix = el.getAttribute('data-suffix') || '';
            const prefix = el.getAttribute('data-prefix') || '';
            const duration = 2000;
            const startTime = performance.now();

            function updateCounter(currentTime) {
                const elapsed = currentTime - startTime;
                const progress = Math.min(elapsed / duration, 1);

                // Ease out cubic
                const eased = 1 - Math.pow(1 - progress, 3);
                const current = Math.round(eased * target);

                el.textContent = prefix + current + suffix;

                if (progress < 1) {
                    requestAnimationFrame(updateCounter);
                }
            }

            requestAnimationFrame(updateCounter);
        });
    }

    window.addEventListener('scroll', animateCounters, { passive: true });

    // --- Smooth Anchor Scrolling ---
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;

            const targetEl = document.querySelector(targetId);
            if (targetEl) {
                e.preventDefault();
                const offset = 80;
                const top = targetEl.getBoundingClientRect().top + window.pageYOffset - offset;
                window.scrollTo({ top, behavior: 'smooth' });
            }
        });
    });

    // --- Download Button Ripple Effect ---
    document.querySelectorAll('.btn-primary').forEach(btn => {
        btn.addEventListener('click', function (e) {
            const ripple = document.createElement('span');
            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);

            ripple.style.cssText = `
                position: absolute;
                width: ${size}px;
                height: ${size}px;
                border-radius: 50%;
                background: rgba(255, 255, 255, 0.3);
                left: ${e.clientX - rect.left - size / 2}px;
                top: ${e.clientY - rect.top - size / 2}px;
                transform: scale(0);
                animation: ripple 0.6s ease-out;
                pointer-events: none;
            `;

            this.style.position = 'relative';
            this.style.overflow = 'hidden';
            this.appendChild(ripple);

            setTimeout(() => ripple.remove(), 600);
        });
    });

    // Add ripple keyframe
    const style = document.createElement('style');
    style.textContent = `
        @keyframes ripple {
            to {
                transform: scale(2.5);
                opacity: 0;
            }
        }
    `;
    document.head.appendChild(style);

    // --- Browser Mockup URL Rotation ---
    const urls = [
        { text: 'https://your-bank.com', safe: true },
        { text: 'http://paypa1-login.xyz/verify', safe: false },
        { text: 'https://github.com', safe: true },
        { text: 'http://amaz0n-update.club/login', safe: false },
        { text: 'https://google.com', safe: true },
    ];

    let currentUrlIndex = 0;
    const urlElement = document.querySelector('.browser-url span');
    const scanResult = document.querySelector('.scan-result');
    const scanResultStrong = scanResult?.querySelector('strong');
    const scanResultSpan = scanResult?.querySelector('span');
    const scanResultSvg = scanResult?.querySelector('svg');

    function rotateUrl() {
        currentUrlIndex = (currentUrlIndex + 1) % urls.length;
        const url = urls[currentUrlIndex];

        // Fade out
        if (urlElement) {
            urlElement.style.transition = 'opacity 0.3s';
            urlElement.style.opacity = '0';
        }
        if (scanResult) {
            scanResult.style.transition = 'opacity 0.3s';
            scanResult.style.opacity = '0';
        }

        setTimeout(() => {
            if (urlElement) {
                urlElement.textContent = url.text;
                urlElement.className = url.safe ? 'url-safe' : 'url-danger';
                urlElement.style.color = url.safe ? '#00e676' : '#ff5252';
                urlElement.style.opacity = '1';
            }

            if (scanResult && scanResultStrong && scanResultSpan && scanResultSvg) {
                if (url.safe) {
                    scanResult.style.background = 'rgba(0, 230, 118, 0.05)';
                    scanResult.style.borderColor = 'rgba(0, 230, 118, 0.15)';
                    scanResultStrong.textContent = 'Website is Safe';
                    scanResultStrong.style.color = '#00e676';
                    scanResultSpan.textContent = `Confidence: ${90 + Math.floor(Math.random() * 10)}% · 0 threats detected`;
                    scanResultSvg.setAttribute('stroke', '#00e676');
                    scanResultSvg.innerHTML = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>';
                } else {
                    scanResult.style.background = 'rgba(255, 82, 82, 0.05)';
                    scanResult.style.borderColor = 'rgba(255, 82, 82, 0.15)';
                    scanResultStrong.textContent = '⚠ Phishing Detected!';
                    scanResultStrong.style.color = '#ff5252';
                    scanResultSpan.textContent = `Confidence: ${75 + Math.floor(Math.random() * 15)}% · High risk`;
                    scanResultSvg.setAttribute('stroke', '#ff5252');
                    scanResultSvg.innerHTML = '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>';
                }
                scanResult.style.opacity = '1';
            }
        }, 400);
    }

    setInterval(rotateUrl, 4000);

})();
