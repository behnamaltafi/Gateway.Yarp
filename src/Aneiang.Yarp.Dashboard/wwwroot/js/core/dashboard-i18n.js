/**
 * Dashboard i18n Helper - Internationalization utilities
 */
(function() {
    'use strict';

    window.DashboardI18n = window.DashboardI18n || {};

    const currentLocale = 'en-US';
    let translations = {};

    window.DashboardI18n.init = function() {
        const dashboard = window.__dashboard;
        // Load translations
        if (dashboard && dashboard.I18N) {
            translations = dashboard.I18N;
        }

    };

    window.__ = function(key, params) {
        // Get translation
        let text = translations[key];

        // Fallback to key if not found
        if (!text) {
            console.warn('[i18n] Missing translation:', key);
            text = key;
        }

        // Replace parameters
        if (params) {
            Object.keys(params).forEach(param => {
                text = text.replace(`{${param}}`, params[param]);
            });
        }

        return text;
    };

    // Alias for module-style access: DashboardI18n.t(key)
    window.DashboardI18n.t = window.__;
    window.DashboardI18n.translations = translations;

    window.DashboardI18n.getLocale = function() {
        return currentLocale;
    };

    window.DashboardI18n.formatDate = function(date, options = {}) {
        const d = typeof date === 'string' ? new Date(date) : date;
        const defaultOptions = {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour12: false
        };
        
        return d.toLocaleString(currentLocale, { ...defaultOptions, ...options });
    };

    window.DashboardI18n.formatTime = function(date, options = {}) {
        const d = typeof date === 'string' ? new Date(date) : date;
        const defaultOptions = {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        };
        
        return d.toLocaleString(currentLocale, { ...defaultOptions, ...options });
    };

    window.DashboardI18n.formatNumber = function(number, options = {}) {
        const defaultOptions = {
            minimumFractionDigits: 0,
            maximumFractionDigits: 2
        };
        
        return new Intl.NumberFormat(currentLocale, { ...defaultOptions, ...options }).format(number);
    };

    window.DashboardI18n.formatBytes = function(bytes, decimals = 2) {
        if (bytes === 0 || bytes === null) return '0 B';
        
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return this.formatNumber(Math.round(bytes / Math.pow(k, i) * Math.pow(10, decimals)) / Math.pow(10, decimals)) + ' ' + sizes[i];
    };

    window.DashboardI18n.isRTL = function() {
        // Currently only support LTR languages
        return false;
    };

})();
