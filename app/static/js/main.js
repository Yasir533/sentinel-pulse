/**
 * Sentinel Pulse - Core JS
 * Initial setup & Console telemetry logger
 */

document.addEventListener('DOMContentLoaded', () => {
    console.log('🛡️ Sentinel Pulse Console Initialized.');
    console.log('📡 Engine status: Awaiting Telemetry Input Connection...');
    
    // Auto-dismiss alert notifications if any are present
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bootstrapAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bootstrapAlert) {
                bootstrapAlert.close();
            }
        }, 5000);
    });

    // Custom Interactive Hover Telemetry Effects (Placeholder)
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            // Subtle sound trigger or glow effect helper can go here in Phase 2
        });
    });
});
