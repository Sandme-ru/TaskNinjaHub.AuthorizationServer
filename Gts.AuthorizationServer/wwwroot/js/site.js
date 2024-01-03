// Please see documentation at https://docs.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

var element = document.querySelector('#PhoneNumber');
if (element !== null) {
    document.addEventListener('DOMContentLoaded', function () {
        var phoneMask = IMask(
            document.getElementById('PhoneNumber'),
            {
                mask: '+7(000)000-00-00'
            });
    });
} else {
    //nothing
}