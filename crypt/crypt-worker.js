var whistle = {};
importScripts('../forge.min.js', '../bcrypt.min.js', 'crypt.js');
self.addEventListener("message", function(e) {
    var data = e.data;
    var method = data.shift();
    try {
        switch (method) {
            case 'start': break;
            default: self.postMessage([null, whistle.crypt[method].apply(this, data)]);
        }
    } catch (err) {
        self.postMessage([{ "message": err.message }]); // Mimic error
    }
});
