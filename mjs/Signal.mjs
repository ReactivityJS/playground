const 
topicMatcher = (a, b) => a === b,

Signal = (eventName = 'Signal', tester = topicMatcher) => ({
    on: (topicPattern, callback) => {
        let handler = e => {
            //console.log("TESTER", e.detail.topic, topicPattern, tester(e.detail.topic, topicPattern))
            tester(e.detail.topic, topicPattern) && callback(...e.detail.args)
        }
        //console.log("SIGNAL ON DEBUG", topicPattern)
        document.addEventListener(eventName, handler)
        return () => document.removeEventListener(eventName, handler)
    },

    emit: (topic, ...args) => {
        //console.log("SIGNAL EMIT DEBUG", eventName, topic)
        document.dispatchEvent(new CustomEvent(eventName, { detail: { topic, args }}))
    }
})

export { Signal }
