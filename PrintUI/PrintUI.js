var app = new Vue({
    el: '#app',
    data: {
        documents: []
    },
    methods: {
        loadDocuments: function () {
            this.documents = [{
                'name': 'Test Document',
                'docID':'Document ID',
                'subject':'Software Design and Development',
                'status':'Digital (PDF)',
                'dScanned':'2020/07/27',
                'comments':'',
                'desc':'There is no description available for this document.',
                'qr':'https://www.google.com/logos/doodles/2020/jeanne-barets-280th-birthday-6753651837108693-l.png'
            // }]
            },{
                'name': 'Test Document',
                'docID':'Document ID',
                'subject':'Software Design and Development',
                'status':'Digital (PDF)',
                'dScanned':'2020/07/27',
                'comments':'',
                'desc':'There is no description available for this document.',
                'qr':'https://www.google.com/logos/doodles/2020/jeanne-barets-280th-birthday-6753651837108693-l.png'
            },{
                'name': 'Test Document',
                'docID':'Document ID',
                'subject':'Software Design and Development',
                'status':'Digital (PDF)',
                'dScanned':'2020/07/27',
                'comments':'',
                'desc':'There is no description available for this document.',
                'qr':'https://www.google.com/logos/doodles/2020/jeanne-barets-280th-birthday-6753651837108693-l.png'
            }]
        },
        invokePrint: function(){
            window.print()
        }
    },
    mounted: function () {
        this.loadDocuments()
        window.print()
        // window.close()
    }
})
