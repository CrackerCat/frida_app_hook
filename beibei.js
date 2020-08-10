Java.perform(function () {

    var SecurityUtils=Java.use("com.husor.beibei.utils.SecurityUtils");
    
    SecurityUtils.a.overload('java.lang.String', 'boolean').implementation=function(arg1,arg2){
        send("a Hook Start...");
        send(arg1)
        send(arg2)
        var result= this.a(arg1,arg2)
        send(result)
        return result
    }
        
    SecurityUtils.a.overload('java.lang.String', 'java.lang.String').implementation=function(arg1,arg2){
        send("a2 Hook Start...");
        send(arg1)
        send(arg2)
        var result= this.a(arg1,arg2)
        send(result)
        return result
    }



    var BaseApiRequest=Java.use("com.husor.beibei.net.BaseApiRequest");
    
    BaseApiRequest.getHost.overload().implementation=function(){
        send("getHost Hook Start...");
        var result= this.getHost()
        send(result)
        return result
    }


});