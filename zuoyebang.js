Java.perform(function () {

    var a=Java.use("com.baidu.homework.common.net.core.a");
    
    a.b.overload().implementation=function(arg1){
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
});