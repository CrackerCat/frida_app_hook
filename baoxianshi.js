Java.perform(function () {

    var d=Java.use("com.rex.generic.rpc.b.d");
    
    d.DESDecrypt.overload('[B', '[B').implementation=function(arg1,arg2){
        // send("list Hook Start...");
        // console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        var result= this.DESDecrypt(arg1,arg2)
        // send(result)
        return result
    }

    var a=Java.use("com.winbaoxian.bxs.service.c.a");
    
    // a.getGeneralLearningListByTabId.overload('java.lang.Long', 'java.lang.Long', 'java.lang.Long', 'java.lang.Long', 'java.lang.Long', 'com.winbaoxian.bxs.service.c.a$j').implementation=function(arg1,arg2,arg3,arg4,arg5,arg6){
    //     send("list Hook Start...");
    //     console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    //     var result= this.DESDecrypt(arg1,arg2,arg3,arg4,arg5,arg6)
    //     // send(result)
    //     return result
    // }


    // var dd=Java.use("com.winbaoxian.bxs.service.c.d");
    // dd.getGeneralLearningListByTabId.overload('java.lang.Long', 'java.lang.Long', 'java.lang.Long', 'java.lang.Long', 'java.lang.Long').implementation=function(arg1,arg2,arg3,arg4,arg5){
    //     send("getGeneralLearningListByTabId Hook Start...");
    //     // console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    //     var result= this.getGeneralLearningListByTabId(arg1,arg2,arg3,arg4,arg5)
    //     // send(result)
    //     return result
    // }

    // var j=Java.use("com.winbaoxian.bxs.service.c.a$j");
    // j.call.overload('java.lang.Long', 'java.lang.Long', 'java.lang.Long', 'java.lang.Long', 'java.lang.Long', 'com.winbaoxian.bxs.service.c.a').implementation=function(arg1,arg2,arg3,arg4,arg5,arg6){
    //     send("call Hook Start...");
    //     // console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    //     var result= this.call(arg1,arg2,arg3,arg4,arg5,arg6)
    //     // send(result)
    //     return result
    // }

    var f=Java.use("com.rex.generic.rpc.b.f");
    f.invoke.overload('com.rex.generic.rpc.b.e', 'java.lang.String', 'com.alibaba.fastjson.JSONObject', 'com.rex.generic.rpc.b.g').implementation=function(arg1,arg2,arg3,arg4){
        send("invoke Hook Start...");
        // console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        send(arg3.toJSONString())
        // send(arg1.getFullUrl(arg2))
        // send(arg1.getMethodPathMap(arg2))
        var result= this.invoke(arg1,arg2,arg3,arg4)
        // send(result)
        send("invoke Hook end...");
        return result
    }

    var HttpPost=Java.use("org.apache.http.client.methods.HttpPost");
    HttpPost.$init.overload('java.lang.String').implementation=function(arg1){
        send("$init Hook Start...");
        // console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        send(arg1)
        var result= this.$init(arg1)
        // send(result)
        send("$init Hook end...");
        return result
    }


    var BXBigContentRecommendList=Java.use("com.winbaoxian.bxs.model.bigContent.BXBigContentRecommendList");
    BXBigContentRecommendList.setOrderNum.overload('java.lang.Long', 'com.alibaba.fastjson.JSONObject').implementation=function(arg1,arg2){
        send("setOrderNum Hook Start...");
        // console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        send(arg1)
        send(arg2.toJSONString())
        var result= this.setOrderNum(arg1,arg2)
        // send(result)
        send("setOrderNum Hook end...");
        return result
    }


});