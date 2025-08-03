/*
 * Client‑side JavaScript for the website gateway
 *
 * This file currently contains only a handful of helpers.  It is prepared for
 * future enhancements such as asynchronous deletions or form validations.
 */

// Placeholder for future JavaScript functionality.  At the moment we simply
// attach confirmation dialogs to elements with the `data-confirm` attribute.
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('button[data-confirm]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const msg = btn.getAttribute('data-confirm') || 'Are you sure?';
            if (!confirm(msg)) {
                e.preventDefault();
            }
        });
    });
});