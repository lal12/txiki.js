// 2nd bootstrap. Here all modules that need to pollute the global namespace are
// already loaded.
//

import { Console } from 'console';
import { defineEventAttribute, EventTarget } from 'event_target';
import { Performance } from 'performance';


// Console
//

Object.defineProperty(window, 'console', {
    enumerable: true,
    configurable: false,
    writable: false,
    value: new Console()
});


// EventTarget
//

Object.defineProperty(window, 'EventTarget', {
    enumerable: true,
    configurable: false,
    writable: false,
    value: EventTarget
});

Object.setPrototypeOf(window, EventTarget.prototype);
EventTarget.call(window);

defineEventAttribute(Object.getPrototypeOf(window), 'load');


// Performance
//

Object.defineProperty(window, 'performance', {
    enumerable: true,
    configurable: false,
    writable: false,
    value: new Performance()
});