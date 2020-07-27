var app = new Vue({
    el:'#app',
    data:{
        documents: []
    },
    methods:{
        loadDocuments: function(){
            this.documents = [{
                'title':'Test'
            }]
        }
    }
})