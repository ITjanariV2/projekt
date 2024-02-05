const pas1 = document.querySelector('#password');
const pas2 = document.querySelector('#confirmPassword');
const sendBtn = document.querySelector('#btn');
const err = document.querySelector('#error');

pas1.addEventListener('input', () => {
    pas1.value.length >= 8 ? pas1.style.border = '2px solid chartreuse' : pas1.style.border = '2px solid red';
});

pas2.addEventListener('input', () => {
    if (pas2.value === pas1.value) {
        pas2.style.border = '2px solid chartreuse';
        err.textContent = '';
        sendBtn.disabled = false;
    } else if (pas2.value !== pas1.value) {
        pas2.style.border = '2px solid red';
        err.textContent = 'Password does not match';
        sendBtn.disabled = true;
    }
});