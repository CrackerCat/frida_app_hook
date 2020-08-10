import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(function () {
    
    var a=Java.use("com.baidu.homework.common.net.core.a");
    send("ok");
    
    a.b.overload("java.util.List").implementation=function(arg1){
        send("list Hook Start...");
        var data="[";
        var it = arg1.iterator();
        while(it.hasNext()){
            var keystr = it.next().toString();
            var map= keystr+',';
            data+=map
        }
        send(data+"]");
        var result= this.b(arg1)
        send(result)
        return result
    }
    
/*
    var TextUtils=Java.use("android.text.TextUtils");
    var String=Java.use("java.lang.String");
    TextUtils.join.overload("java.lang.CharSequence","java.lang.Iterable").implementation=function(arg1,arg2){
        
        var ishook=false
        var it = arg2.iterator();
        var key =""
        while(it.hasNext()){
            var keystr = it.next().toString();
            if(keystr.indexOf("_t_")==0){
                key =keystr
            }

        }
        send(">>>>"+key);
        var result= this.join(arg1,arg2)
        result=result.replace(key,"_t_=1592543155")
        send(result)
        return result
    }
    */



});
"""

process = frida.get_usb_device().attach('com.baidu.homework')
script = process.create_script(jscode)
script.on('message', on_message)
script.load()
sys.stdin.read()