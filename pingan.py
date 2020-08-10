import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(function () {

    var util=Java.use("com.pingan.hrx.commons.util");
    util.punch.overload("java.lang.String").implementation=function(arg1){
        send("punch Hook Start...");
        var result = this.punch(arg1)
        return result
    }
});
"""

process = frida.get_usb_device().attach('com.pingan.hrxapp')
script = process.create_script(jscode)
script.on('message', on_message)
script.load()
sys.stdin.read()