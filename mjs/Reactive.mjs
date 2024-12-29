import { Signal } from '//raw.githack.com/ReactivityJS/playground/main/mjs/Signal.mjs'

const 
ReactiveHandler = (name, Event) => ({
    get: (target, property, proxy) => {
        //console.log("PROP GET", property, target[property])
        if(property === '$on') {
            return (callback, prop) => {
                if(!prop || prop === '?') {
                    prop = name + '?'
                } else if(prop === '*') {
                    prop = name + '.*'
                } else {
                    prop = `${name}.${prop}`
                }
                //console.log("TOPIC DEBUG", prop)
                return Event.on(prop, callback)
            }
        }
        if (['[object Object]', '[object Array]', '[object Function]'].indexOf(Object.prototype.toString.call(target[property])) > -1) { // Array, Object and Function "magic" :)
            return new Proxy(target[property], ReactiveHandler(`${name}.${property}`, Event))
        } 
        return target[property]
    },
    /**
     * @todo recursive loop during creating step by step...
     */
    set: (target, property, value, proxy) => {
        //console.log("SET", property, value)
        if(target[property] !== value) {
            let 
            action = 'set',
            topic = `${name}.${property}`,
            oldValue = target[property]
            target[property] = value
            Event.emit(topic, value, property, topic, action, oldValue, proxy)
        }
        return true
    },
    deleteProperty: (target, property) => {
        //console.log("DEL", property, target[property])
        if(target[property]) {
            let 
            action = 'del',
            topic = `${name}.${property}`,
            oldValue = target[property],
            proxy = new Proxy(target, ReactiveHandler(name, Event))
            delete target[property]
            Event.emit(topic, target[property], property, topic, action, oldValue, proxy)
        }
        return true
    },
    apply: (target, thisArg, args) => {
        //console.log("APPLY")
        let
        result = target.apply(thisArg, args),
        action = 'apply', 
        topic = `${name}.${action}`,
        proxy = new Proxy(target, ReactiveHandler(name, Event))
        Event.emit(topic, result, action, topic, action, target, proxy)
        return result
    },
    construct: (target, args, constructor) => {
        //console.log("CONSTRUCT")
        let 
        action = 'construct',
        result = new target(...args),
        topic = `${name}.${action}`,
        proxy = new Proxy(target, ReactiveHandler(name, Event))
        Event.emit(topic, result, action, topic, action, target, proxy)
        return result
    }
}),

/**
 * // create Reactive data
 * data = Reactive({})
 * data = Reactive({ app1: { name: "MyApp", version: 1, author: "me" }})
 * 
 * // add listener...
 * data.app1.$on((...args) => console.log("LISTENER property 'name'", ...args)) // default property "?" -> object and optional properties too
 * data.app1.$on((...args) => console.log("LISTENER property 'name'", ...args), 'name')
 * data.app1.$on((...args) => console.log("LISTENER all properties", ...args), '*')
 * 
 * // change data to trigger listeners...
 * data.app1.name = "Bum!"
 */
Reactive = (data = {}, reactiveName = "Reactive", signalName = 'Signal', Event = Signal(`${signalName}:${reactiveName}`)) => new Proxy(data, ReactiveHandler(reactiveName, Event))

export { Reactive }
