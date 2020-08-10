Java.perform(function () {

    var ContentWebView=Java.use("com.jifen.qukan.content.web.view.ContentWebView");
    ContentWebView.getWeb.overload().implementation=function(){
        send("getWeb Hook Start...");
        var result =  this.getWeb()
        result.setWebContentsDebuggingEnabled(true)
        //send(result.getClass().getName())
        return result
    }

    var QWrapScrollWebView=Java.use("com.jifen.qkbase.web.view.wrap.QWrapScrollWebView");
    QWrapScrollWebView.loadUrl.overload("java.lang.String").implementation=function(arg1){
        send("loadUrl Hook Start 这里已经从java返回数据了...");
        // console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        // send(arg1)
        var result =  this.loadUrl(arg1)
        return result
    }


    var f=Java.use("com.jifen.framework.http.napi.ok.f");
    f.a.overload('com.jifen.framework.http.napi.b', 'com.jifen.framework.http.napi.HttpRequest', 'com.jifen.framework.http.napi.HttpRequestHandler').implementation=function(arg1, arg2,arg3){
        // send("okhttp Hook Start...");
        send(arg2.url())
        var result =  this.a(arg1,arg2,arg3)
        return result
    }

    f.e.overload().implementation=function(){
        send("e Hook Start...");
        var result =  this.e()
        return result
    }


    var InnerJavascriptInterface=Java.use("com.jifen.qu.open.web.bridge.basic.InnerJavascriptInterface");
    InnerJavascriptInterface.getInnerParameter.overload('java.lang.String','java.lang.String').implementation=function(arg1,arg2){
        send("getInnerParameter Hook Start...");
        send(arg2)
        var result =  this.getInnerParameter(arg1,arg2)
        return result
    }
    // var InnerJavascriptInterface=Java.use("com.jifen.framework.web.bridge.basic.DWebView$InnerJavascriptInterface");
    // InnerJavascriptInterface.call.overload('java.lang.String','java.lang.String').implementation=function(arg1,arg2){
    //     send("call Hook Start...");
    //     send(arg2.url())
    //     var result =  this.call(arg1,arg2)
    //     return result
    // }
    // var InnerJavascriptInterface=Java.use("com.jifen.framework.web.bridge.basic.jspackage.DJsPackage$InnerJavascriptInterface");
    // InnerJavascriptInterface.call.overload('java.lang.String','java.lang.String').implementation=function(arg1,arg2){
    //     send("call Hook Start...");
    //     // send(arg2.url())
    //     send(arg1)
    //     send(arg2)
    //     var result =  this.call(arg1,arg2)
    //     return result
    // }

    // jsbriage
    // var DJsPackage=Java.use("com.jifen.framework.web.bridge.basic.jspackage.DJsPackage");
    // DJsPackage.d.overload('java.lang.String').implementation=function(arg1){
    //     send("d Hook Start...");
    //     send(arg1)
    //     var result =  this.d(arg1)
    //     send(result)
    //     // send(this.f.value)
    //     return result
    // }

    // var aaa=Java.use("com.jifen.framework.core.a.a");
    // aaa.a.overload('java.lang.String','java.lang.String').implementation=function(arg1,arg2){
    //     // send("call Hook Start...");
    //     // send(arg2.url())
    //     // send(arg1)
    //     send(arg2)
    //     var result =  this.a(arg1,arg2)
    //     return result
    // }

    
    var NativeUtils=Java.use("com.jifen.qukan.utils.NativeUtils");
    NativeUtils.getInnoSoInfo.overload("java.lang.String").implementation=function(arg1){
        send("getInnoSoInfo");
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        send(arg1)
        var result = this.getInnoSoInfo(arg1)
        send(result)
        return result
    }
    
});


// message: {'type': 'send', 'payload': 'com.jifen.qukan.web.api.BasicApi'} data: None
// message: {'type': 'send', 'payload': 'askAsynData'} data: None