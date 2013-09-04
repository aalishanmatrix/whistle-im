/*
 * whistle.im browser cryptography library
 * Copyright (C) 2013 Daniel Wirtz - http://dcode.io
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
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
