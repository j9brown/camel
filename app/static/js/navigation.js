document.getElementById('refresh-button')?.addEventListener('click', () => {
    window.location.reload();
});

document.getElementById('back-button')?.addEventListener('click', () => {
    history.back();
});
