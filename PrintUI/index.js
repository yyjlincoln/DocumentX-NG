var app = new Vue({
    el: '#app',
    data: {
        ready:true,
        documents:[],
        showAllDocs:false
    },
    methods:{
        NewDoc:function(){
            window.open("FileUpload.html","newwindow","width=auto")
        },
        ViewAllDoc:function(){
            window.open("AllDoc.html","newwindow","width=auto")
        }
    }
})