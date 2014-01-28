module.exports = function (grunt) {

    // Project configuration
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),
        jshint: {
            all: ['src/*.js', 'Gruntfile.js', 'test/test.js'],
            options: {
                loopfunc: true
            }
        },
        qunit: {
            all: ['test/index.html']
        },
        jsdoc: {
            dist: {
                src: ['src/*.js'],
                options: {
                    destination: 'doc',
                    template: 'docstrap'
                }
            }
        },
        concat: {
            options: {
                banner: '/*\n<%= pkg.title %> v<%= pkg.version %>\n<%= pkg.homepage %>\nCopyright (c) 2013 <%= pkg.author.name %>\n<%= pkg.license.url %>\n*/\n\n',
                separator: '\n\n'
            },
            dist: {
                src: [
                    'src/core.js',
                    'src/core.js',
                    'src/cryptography.js',
                    'src/encoding.js',
                    'src/endpoint.js',
                    'src/tx.js',
                    'src/wallet.js',
                    'src/blockchain.js'
                ],
                dest: 'dist/<%= pkg.name %>.min.js'
            }
        }
    });

    // Plugins
    grunt.loadNpmTasks('grunt-contrib-jshint');
    grunt.loadNpmTasks('grunt-contrib-qunit');
    grunt.loadNpmTasks('grunt-contrib-concat');
    grunt.loadNpmTasks('grunt-jsdoc');

    // Tasks
    grunt.registerTask('default', ['jshint', 'concat', 'qunit']);
    grunt.registerTask('doc', ['jshint', 'qunit', 'jsdoc']);

};