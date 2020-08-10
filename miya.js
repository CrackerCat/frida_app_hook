Java.perform(function () {

    var g=Java.use("com.mia.miababy.utils.g");
    
    g.a.overload('java.lang.String', 'java.lang.String').implementation=function(arg1,arg2){
        send("a Hook Start...");
        send(arg1)
        send(arg2)
        var result= this.a(arg1,arg2)
        send(result)
        return result
    }
    g.b.overload('java.lang.String').implementation=function(arg1){
        send("a Hook Start...");
        send(arg1)
        var result= this.b(arg1)
        send(result)
        return result
    }
    
});