//
// This software is released under the 3-clause BSD license.
//
// Copyright (c) 2015, Xin Chen <txchen@gmail.com>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//     * Neither the name of the author nor the
//       names of its contributors may be used to endorse or promote products
//       derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL COPYRIGHT HOLDER BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Github site: https://github.com/chenx/MidiPlayer

/*
由于在安卓上测试最新的audioWorklet失败，因此继续使用createScriptProcessor
        // 在main.html中使用
        async function initMidi() {
            try {
                const AudioContext = window.AudioContext || window.webkitAudioContext;
                const myAudioContext = new AudioContext();
                await myAudioContext.audioWorklet.addModule('midi.js'); // 在安卓上还没有audioWorklet
                const node = new AudioWorkletNode(myAudioContext, 'midi');
                node.connect(myAudioContext.destination)
                return {
                    AudioContext: myAudioContext,
                    node: node,
                    play: function (midi, isLoop) {
                        node.port.postMessage({ cmd: 'play', midi, isLoop });
                    },
                    stop: function () {
                        node.port.postMessage({ cmd: 'stop' });
                    }
                }
            } catch (e) {
                alert(e)
            }
        }
*/

/*
// 新的audioWorklet实现，安卓上测试失败
class WhiteNoiseProcessor extends AudioWorkletProcessor {
    generator = null;
    midi = null;
    isLoop = false;

    constructor(...args) {
        super(...args);
        Midi.setSampleRate(sampleRate);
        this.port.onmessage = this.onmessage.bind(this);
    }
    onmessage(e) {
        switch (e.data.cmd) {
            case 'play': {
                this.midi = Midi.MidiFile(e.data.midi);
                this.play(e.data.isLoop);
                break;
            }
            case 'stop': {
                this.stop();
                break;
            }
            default:
                console.log('unknown cmd');
        }
    }
    play(isLoop) {
        this.isLoop = isLoop;
        this.generator = Midi.Replayer(this.midi);
    }
    stop() {
        this.generator.finished = true;
        this.isLoop = false;
    }
    process(inputs, outputs, parameters) {
        if (this.generator) {
            if (this.generator.finished) {
                if (this.isLoop) {
                    this.play(this.isLoop);
                } else {
                    return true;
                }
            }
            const channel = outputs[0][0];
            const generate = this.generator.generate(channel.length);
            for (let i = 0; i < channel.length; i++) {
                channel[i] = generate[i * 2];
            }
        }
        return true
    }
}
registerProcessor('midi', WhiteNoiseProcessor)
*/

function MidiPlayer() {
    return {
        isInited: false,
        generator: null,
        midi: null,
        isLoop: false,
        node: null,
        context: null,

        init: function () {
            this.isInited = true;
            this.context = new AudioContext();
            this.node = this.context.createScriptProcessor(4096 * 4, 0, 1);
            const obj = this;

            Midi.setSampleRate(this.context.sampleRate);

            this.node.onaudioprocess = function (e) {
                if (obj.generator) {
                    if (obj.generator.finished) {
                        if (obj.isLoop) {
                            obj.generator = Midi.Replayer(obj.midi);
                        } else {
                            return;
                        }
                    }
                    const channel = e.outputBuffer.getChannelData(0);
                    const generate = obj.generator.generate(channel.length);
                    for (let i = 0; i < channel.length; i++) {
                        channel[i] = generate[i * 2];
                    }
                }
            }
        },
        play: function (midiData, isLoop) {
            if (!this.isInited) { this.init() }
            this.midi = Midi.MidiFile(midiData);
            this.isLoop = isLoop;
            this.generator = Midi.Replayer(this.midi);
            this.node.connect(this.context.destination);
        },
        stop: function () {
            if (!this.isInited) { this.init() }
            if (this.generator) {
                this.isLoop = false;
                this.generator.finished = true;
            }
            this.node.disconnect();
        },
    }

}

var Midi = (function () {
    var sampleRate = 44100;

    function MidiFile(data) {
        var stream = Stream(data);

        function readChunk(stream) {
            var id = stream.readInt32();
            var length = stream.readInt32();
            return {
                'id': id,
                'length': length,
                'data': stream.read(length)
            };
        }

        var lastEventTypeByte;

        function readEvent(stream) {
            var event = {};
            event.deltaTime = stream.readVarInt();
            var eventTypeByte = stream.readInt8();
            if ((eventTypeByte & 0xf0) == 0xf0) {
                /* system / meta event */
                if (eventTypeByte == 0xff) {
                    /* meta event */
                    event.type = 'meta';
                    var subtypeByte = stream.readInt8();
                    var length = stream.readVarInt();
                    switch (subtypeByte) {
                        case 0x00:
                            event.subtype = 'sequenceNumber';
                            if (length != 2) throw "Expected length for sequenceNumber event is 2, got " + length;
                            event.number = stream.readInt16();
                            return event;
                        case 0x01:
                            event.subtype = 'text';
                            event.text = stream.read(length);
                            return event;
                        case 0x02:
                            event.subtype = 'copyrightNotice';
                            event.text = stream.read(length);
                            return event;
                        case 0x03:
                            event.subtype = 'trackName';
                            event.text = stream.read(length);
                            return event;
                        case 0x04:
                            event.subtype = 'instrumentName';
                            event.text = stream.read(length);
                            return event;
                        case 0x05:
                            event.subtype = 'lyrics';
                            event.text = stream.read(length);
                            return event;
                        case 0x06:
                            event.subtype = 'marker';
                            event.text = stream.read(length);
                            return event;
                        case 0x07:
                            event.subtype = 'cuePoint';
                            event.text = stream.read(length);
                            return event;
                        case 0x20:
                            event.subtype = 'midiChannelPrefix';
                            if (length != 1) throw "Expected length for midiChannelPrefix event is 1, got " + length;
                            event.channel = stream.readInt8();
                            return event;
                        case 0x2f:
                            event.subtype = 'endOfTrack';
                            if (length != 0) throw "Expected length for endOfTrack event is 0, got " + length;
                            return event;
                        case 0x51:
                            event.subtype = 'setTempo';
                            if (length != 3) throw "Expected length for setTempo event is 3, got " + length;
                            event.microsecondsPerBeat = (
                                (stream.readInt8() << 16)
                                + (stream.readInt8() << 8)
                                + stream.readInt8()
                            )
                            return event;
                        case 0x54:
                            event.subtype = 'smpteOffset';
                            if (length != 5) throw "Expected length for smpteOffset event is 5, got " + length;
                            var hourByte = stream.readInt8();
                            event.frameRate = {
                                0x00: 24, 0x20: 25, 0x40: 29, 0x60: 30
                            }[hourByte & 0x60];
                            event.hour = hourByte & 0x1f;
                            event.min = stream.readInt8();
                            event.sec = stream.readInt8();
                            event.frame = stream.readInt8();
                            event.subframe = stream.readInt8();
                            return event;
                        case 0x58:
                            event.subtype = 'timeSignature';
                            if (length != 4) throw "Expected length for timeSignature event is 4, got " + length;
                            event.numerator = stream.readInt8();
                            event.denominator = Math.pow(2, stream.readInt8());
                            event.metronome = stream.readInt8();
                            event.thirtyseconds = stream.readInt8();
                            return event;
                        case 0x59:
                            event.subtype = 'keySignature';
                            if (length != 2) throw "Expected length for keySignature event is 2, got " + length;
                            event.key = stream.readInt8(true);
                            event.scale = stream.readInt8();
                            return event;
                        case 0x7f:
                            event.subtype = 'sequencerSpecific';
                            event.data = stream.read(length);
                            return event;
                        default:
                            // console.log("Unrecognised meta event subtype: " + subtypeByte);
                            event.subtype = 'unknown'
                            event.data = stream.read(length);
                            return event;
                    }
                    event.data = stream.read(length);
                    return event;
                } else if (eventTypeByte == 0xf0) {
                    event.type = 'sysEx';
                    var length = stream.readVarInt();
                    event.data = stream.read(length);
                    return event;
                } else if (eventTypeByte == 0xf7) {
                    event.type = 'dividedSysEx';
                    var length = stream.readVarInt();
                    event.data = stream.read(length);
                    return event;
                } else {
                    throw "Unrecognised MIDI event type byte: " + eventTypeByte;
                }
            } else {
                /* channel event */
                var param1;
                if ((eventTypeByte & 0x80) == 0) {
                    /* running status - reuse lastEventTypeByte as the event type.
                        eventTypeByte is actually the first parameter
                    */
                    param1 = eventTypeByte;
                    eventTypeByte = lastEventTypeByte;
                } else {
                    param1 = stream.readInt8();
                    lastEventTypeByte = eventTypeByte;
                }
                var eventType = eventTypeByte >> 4;
                event.channel = eventTypeByte & 0x0f;
                event.type = 'channel';
                switch (eventType) {
                    case 0x08:
                        event.subtype = 'noteOff';
                        event.noteNumber = param1;
                        event.velocity = stream.readInt8();
                        return event;
                    case 0x09:
                        event.noteNumber = param1;
                        event.velocity = stream.readInt8();
                        if (event.velocity == 0) {
                            event.subtype = 'noteOff';
                        } else {
                            event.subtype = 'noteOn';
                        }
                        return event;
                    case 0x0a:
                        event.subtype = 'noteAftertouch';
                        event.noteNumber = param1;
                        event.amount = stream.readInt8();
                        return event;
                    case 0x0b:
                        event.subtype = 'controller';
                        event.controllerType = param1;
                        event.value = stream.readInt8();
                        return event;
                    case 0x0c:
                        event.subtype = 'programChange';
                        event.programNumber = param1;
                        return event;
                    case 0x0d:
                        event.subtype = 'channelAftertouch';
                        event.amount = param1;
                        return event;
                    case 0x0e:
                        event.subtype = 'pitchBend';
                        event.value = param1 + (stream.readInt8() << 7);
                        return event;
                    default:
                        throw "Unrecognised MIDI event type: " + eventType
                    /* 
                    console.log("Unrecognised MIDI event type: " + eventType);
                    stream.readInt8();
                    event.subtype = 'unknown';
                    return event;
                    */
                }
            }
        }

        var headerChunk = readChunk(stream);
        if (headerChunk.id != 0x4D546864 || headerChunk.length != 6) {
            throw "Bad .mid file - header not found";
        }
        var headerStream = Stream(headerChunk.data);
        var formatType = headerStream.readInt16();
        var trackCount = headerStream.readInt16();
        var timeDivision = headerStream.readInt16();

        if (timeDivision & 0x8000) {
            throw "Expressing time division in SMTPE frames is not supported yet"
        }

        var header = {
            'formatType': formatType,
            'trackCount': trackCount,
            'ticksPerBeat': timeDivision
        }
        var tracks = [];
        for (var i = 0; i < header.trackCount; i++) {
            tracks[i] = [];
            var trackChunk = readChunk(stream);
            if (trackChunk.id != 0x4D54726B) {
                throw "Unexpected chunk - expected MTrk, got " + trackChunk.id;
            }
            var trackStream = Stream(trackChunk.data);
            while (!trackStream.eof()) {
                var event = readEvent(trackStream);
                tracks[i].push(event);
                //console.log(event);
            }
        }

        return {
            'header': header,
            'tracks': tracks
        }
    }

    function Replayer(midiFile) {
        var generators = [];
        var trackStates = [];
        var beatsPerMinute = 120;
        var ticksPerBeat = midiFile.header.ticksPerBeat;
        var channelCount = 16;

        for (var i = 0; i < midiFile.tracks.length; i++) {
            trackStates[i] = {
                'nextEventIndex': 0,
                'ticksToNextEvent': (midiFile.tracks[i].length ? midiFile.tracks[i][0].deltaTime : null)
            };
        }

        function Channel() {

            var generatorsByNote = {};
            var currentProgram = PianoProgram;

            function noteOn(note, velocity) {
                if (generatorsByNote[note] && !generatorsByNote[note].released) {
                    /* playing same note before releasing the last one. BOO */
                    generatorsByNote[note].noteOff(); /* TODO: check whether we ought to be passing a velocity in */
                }
                var generator = currentProgram.createNote(note, velocity);
                generators.push(generator);
                generatorsByNote[note] = generator;
            }
            function noteOff(note, velocity) {
                if (generatorsByNote[note] && !generatorsByNote[note].released) {
                    generatorsByNote[note].noteOff(velocity);
                }
            }
            function setProgram(programNumber) {
                currentProgram = PROGRAMS[programNumber] || PianoProgram;
            }

            return {
                'noteOn': noteOn,
                'noteOff': noteOff,
                'setProgram': setProgram
            }
        }

        var channels = [];
        for (var i = 0; i < channelCount; i++) {
            channels[i] = Channel();
        }

        var nextEventInfo;
        var samplesToNextEvent = 0;

        function getNextEvent() {
            var ticksToNextEvent = null;
            var nextEventTrack = null;
            var nextEventIndex = null;

            for (var i = 0; i < trackStates.length; i++) {
                if (
                    trackStates[i].ticksToNextEvent != null
                    && (ticksToNextEvent == null || trackStates[i].ticksToNextEvent < ticksToNextEvent)
                ) {
                    ticksToNextEvent = trackStates[i].ticksToNextEvent;
                    nextEventTrack = i;
                    nextEventIndex = trackStates[i].nextEventIndex;
                }
            }
            if (nextEventTrack != null) {
                /* consume event from that track */
                var nextEvent = midiFile.tracks[nextEventTrack][nextEventIndex];
                if (midiFile.tracks[nextEventTrack][nextEventIndex + 1]) {
                    trackStates[nextEventTrack].ticksToNextEvent += midiFile.tracks[nextEventTrack][nextEventIndex + 1].deltaTime;
                } else {
                    trackStates[nextEventTrack].ticksToNextEvent = null;
                }
                trackStates[nextEventTrack].nextEventIndex += 1;
                /* advance timings on all tracks by ticksToNextEvent */
                for (var i = 0; i < trackStates.length; i++) {
                    if (trackStates[i].ticksToNextEvent != null) {
                        trackStates[i].ticksToNextEvent -= ticksToNextEvent
                    }
                }
                nextEventInfo = {
                    'ticksToEvent': ticksToNextEvent,
                    'event': nextEvent,
                    'track': nextEventTrack
                }
                var beatsToNextEvent = ticksToNextEvent / ticksPerBeat;
                var secondsToNextEvent = beatsToNextEvent / (beatsPerMinute / 60);
                samplesToNextEvent += secondsToNextEvent * sampleRate;
            } else {
                nextEventInfo = null;
                samplesToNextEvent = null;
                self.finished = true;
            }
        }

        getNextEvent();

        function generateIntoBuffer(samplesToGenerate, buffer, offset) {
            for (var i = offset; i < offset + samplesToGenerate * 2; i++) {
                buffer[i] = 0;
            }
            for (var i = generators.length - 1; i >= 0; i--) {
                generators[i].generate(buffer, offset, samplesToGenerate);
                if (!generators[i].alive) generators.splice(i, 1);
            }
        }

        function generate(samples) {
            var data = new Array(samples * 2);
            var samplesRemaining = samples;
            var dataOffset = 0;

            while (true) {
                if (samplesToNextEvent != null && samplesToNextEvent <= samplesRemaining) {
                    /* generate samplesToNextEvent samples, process event and repeat */
                    var samplesToGenerate = Math.ceil(samplesToNextEvent);
                    if (samplesToGenerate > 0) {
                        generateIntoBuffer(samplesToGenerate, data, dataOffset);
                        dataOffset += samplesToGenerate * 2;
                        samplesRemaining -= samplesToGenerate;
                        samplesToNextEvent -= samplesToGenerate;
                    }

                    handleEvent();
                    getNextEvent();
                } else {
                    /* generate samples to end of buffer */
                    if (samplesRemaining > 0) {
                        generateIntoBuffer(samplesRemaining, data, dataOffset);
                        samplesToNextEvent -= samplesRemaining;
                    }
                    break;
                }
            }
            return data;
        }

        function handleEvent() {
            var event = nextEventInfo.event;
            switch (event.type) {
                case 'meta':
                    switch (event.subtype) {
                        case 'setTempo':
                            beatsPerMinute = 60000000 / event.microsecondsPerBeat
                    }
                    break;
                case 'channel':
                    switch (event.subtype) {
                        case 'noteOn':
                            channels[event.channel].noteOn(event.noteNumber, event.velocity);
                            break;
                        case 'noteOff':
                            channels[event.channel].noteOff(event.noteNumber, event.velocity);
                            break;
                        case 'programChange':
                            //console.log('program change to ' + event.programNumber);
                            channels[event.channel].setProgram(event.programNumber);
                            break;
                    }
                    break;
            }
        }

        var self = {
            'generate': generate,
            'finished': false
        }
        return self;
    }

    function Stream(data) {
        const dv = new DataView(data);
        var position = 0;

        return {
            read: function (length) {
                var end = position + length;
                var ret = data.slice(position, end);
                position = end;
                return ret;
            },
            readInt32: function () {
                var result = dv.getInt32(position, false);
                position += 4;
                return result;
            },
            readInt16: function () {
                var result = dv.getInt16(position, false);
                position += 2;
                return result;
            },
            readInt8: function (signed) {
                var result = signed ? dv.getInt8(position) : dv.getUint8(position);
                position += 1;
                return result;
            },
            eof: function () {
                return position >= dv.byteLength;
            },
            /* read a MIDI-style variable-length integer
               (big-endian value in groups of 7 bits, with top bit set to signify that another byte follows)
            */
            readVarInt: function () {
                var result = 0;
                while (true) {
                    var b = this.readInt8();
                    if (b & 0x80) {
                        result += (b & 0x7f);
                        result <<= 7;
                    } else { /* b is the last byte */
                        return result + b;
                    }
                }
            }
        };
    }

    function SineGenerator(freq) {
        var self = { 'alive': true };
        var period = sampleRate / freq;
        var t = 0;

        self.generate = function (buf, offset, count) {
            for (; count; count--) {
                var phase = t / period;
                var result = Math.sin(phase * 2 * Math.PI);
                buf[offset++] += result;
                buf[offset++] += result;
                t++;
            }
        }

        return self;
    }

    function SquareGenerator(freq, phase) {
        var self = { 'alive': true };
        var period = sampleRate / freq;
        var t = 0;

        self.generate = function (buf, offset, count) {
            for (; count; count--) {
                var result = ((t / period) % 1 > phase ? 1 : -1);
                buf[offset++] += result;
                buf[offset++] += result;
                t++;
            }
        }

        return self;
    }

    function ADSRGenerator(child, attackAmplitude, sustainAmplitude, attackTimeS, decayTimeS, releaseTimeS) {
        var self = { 'alive': true }
        var attackTime = sampleRate * attackTimeS;
        var decayTime = sampleRate * (attackTimeS + decayTimeS);
        var decayRate = (attackAmplitude - sustainAmplitude) / (decayTime - attackTime);
        var releaseTime = null; /* not known yet */
        var endTime = null; /* not known yet */
        var releaseRate = sustainAmplitude / (sampleRate * releaseTimeS);
        var t = 0;

        self.noteOff = function () {
            if (self.released) return;
            releaseTime = t;
            self.released = true;
            endTime = releaseTime + sampleRate * releaseTimeS;
        }

        self.generate = function (buf, offset, count) {
            if (!self.alive) return;
            var input = new Array(count * 2);
            for (var i = 0; i < count * 2; i++) {
                input[i] = 0;
            }
            child.generate(input, 0, count);

            var childOffset = 0;
            while (count) {
                if (releaseTime != null) {
                    if (t < endTime) {
                        /* release */
                        while (count && t < endTime) {
                            var ampl = sustainAmplitude - releaseRate * (t - releaseTime);
                            buf[offset++] += input[childOffset++] * ampl;
                            buf[offset++] += input[childOffset++] * ampl;
                            t++;
                            count--;
                        }
                    } else {
                        /* dead */
                        self.alive = false;
                        return;
                    }
                } else if (t < attackTime) {
                    /* attack */
                    while (count && t < attackTime) {
                        var ampl = attackAmplitude * t / attackTime;
                        buf[offset++] += input[childOffset++] * ampl;
                        buf[offset++] += input[childOffset++] * ampl;
                        t++;
                        count--;
                    }
                } else if (t < decayTime) {
                    /* decay */
                    while (count && t < decayTime) {
                        var ampl = attackAmplitude - decayRate * (t - attackTime);
                        buf[offset++] += input[childOffset++] * ampl;
                        buf[offset++] += input[childOffset++] * ampl;
                        t++;
                        count--;
                    }
                } else {
                    /* sustain */
                    while (count) {
                        buf[offset++] += input[childOffset++] * sustainAmplitude;
                        buf[offset++] += input[childOffset++] * sustainAmplitude;
                        t++;
                        count--;
                    }
                }
            }
        }

        return self;
    }

    function midiToFrequency(note) {
        return 440 * Math.pow(2, (note - 69) / 12);
    }

    var PianoProgram = {
        'attackAmplitude': 0.2,
        'sustainAmplitude': 0.1,
        'attackTime': 0.02,
        'decayTime': 0.3,
        'releaseTime': 0.02,
        'createNote': function (note, velocity) {
            var frequency = midiToFrequency(note);
            return ADSRGenerator(
                SineGenerator(frequency),
                this.attackAmplitude * (velocity / 128), this.sustainAmplitude * (velocity / 128),
                this.attackTime, this.decayTime, this.releaseTime
            );
        }
    }

    var StringProgram = {
        'createNote': function (note, velocity) {
            var frequency = midiToFrequency(note);
            return ADSRGenerator(
                SineGenerator(frequency),
                0.5 * (velocity / 128), 0.2 * (velocity / 128),
                0.4, 0.8, 0.4
            );
        }
    }

    var PROGRAMS = {
        41: StringProgram,
        42: StringProgram,
        43: StringProgram,
        44: StringProgram,
        45: StringProgram,
        46: StringProgram,
        47: StringProgram,
        49: StringProgram,
        50: StringProgram
    };

    function setSampleRate(rate) {
        console.log('new sampleRate:', rate);
        sampleRate = rate;
    }
    return { MidiFile, Replayer, setSampleRate };
})();