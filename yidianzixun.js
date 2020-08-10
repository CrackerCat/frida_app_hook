Java.perform(function () {

    var SignUtil=Java.use("com.yidian.news.util.sign.SignUtil");
    
    SignUtil.a.overload('android.content.Context','java.lang.String').implementation=function(arg1,arg2){
        send("list Hook Start...");
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        send(arg2)
        var result= this.a(arg1,arg2)
        send(result)
        return result
    }
});