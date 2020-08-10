import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(function () {

    var d=Java.use("com.rex.generic.rpc.b.d");
    
    d.DESDecrypt.overload().implementation=function(arg1,arg2){
        send("list Hook Start...");
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        var result= this.DESDecrypt(arg1,arg2)
        send(result)
        return result
    }
});
"""

device = frida.get_device_manager().enumerate_devices()[-1]
pid = device.spawn(["com.winbaoxian.wybx"])
session = device.attach(pid)
print("[*] Attach Application id:",pid)
device.resume(pid)
print("[*] Application onResume")
script = session.create_script(jscode)
'''
process = frida.get_usb_device().attach("cn.thecover.www.covermedia")
script = process.create_script(jscode)
'''
script.on('message', on_message)
print('[*] Running CTF')
script.load()
sys.stdin.read()


"""
GET /search/searchContentNew?dtu=188201&tk=ACF4Ucq4QaBoLiOzWWzlrceFkjFxVjivAy00NzUxNDk1MDg5NTIyNQ&lon=0.0&token=bf120PJ1OlRfaDBnUkqlUFHHRSMkpXwWbeUQGvBF66IkFMloTFxu5zAVIgxdBDMWgzU3-bm49vq97GHnDQ&guid=8f656371630655f06e640945987.03049826&abCoinTask=0.0&uuid=13fa2dd2d7dc48ab81319805028fd96a&tuid=eFHKuEGgaC4js1ls5a3HhQ&tabCode=3&oaid=&distinct_id=534de2e7cf5b4d23&version=30985000&keyword=%25E5%25A4%25A7%25E6%25B1%259F%25E8%2583%25A1%25E5%2590%258C&traceId=bc719f780ad1ab0ba031c1e5448edbfe&keywordSource=history&page=1&deviceCode=867686023840729&limit=20.0&sign=a07916f1f7313d37fc55d93b57dd9aa3&time=1594725615096&id_version=1000&is_pure=0&h5_zip_version=1007&versionName=3.9.85.000.0702.1633&network=wifi&OSVersion=6.0.1&searchSource=0.0&device_code=867686023840729&lat=0.0 HTTP/1.1
X-Tk: ACF4Ucq4QaBoLiOzWWzlrceFkjFxVjivAy00NzUxNDk1MDg5NTIyNQ
X-Qtt-Hitexpids: 1,52735,53933,67782,67811,69356,71848,73438,73448,73587,73615,73630,74078,74399,74404,74557,74681,75401,75463,75707,75762,75800,75936,75966,76022,76171,76289,76345,76354,76379,76592,76600,76619,76628,76655
X-Qtt-Exptimestamp: 1594725492
Host: api.1sapp.com
Connection: Keep-Alive
Accept-Encoding: gzip
User-Agent: okhttp/3.12.0

m1771a
"""