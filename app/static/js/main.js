/**
 * Sentinel Pulse — Core Application JS (Version 2.0 RC-2)
 */

document.addEventListener('DOMContentLoaded', () => {
    // Auto-dismiss flash alert notifications after 5 seconds
    document.querySelectorAll('.alert-dismissible').forEach(alert => {
        setTimeout(() => {
            const instance = bootstrap.Alert.getOrCreateInstance(alert);
            if (instance) instance.close();
        }, 5000);
    });
});
