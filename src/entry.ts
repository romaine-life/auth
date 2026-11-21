// The image's entrypoint: the server, or with --self-test the image checking itself
// (pipeline-templates' release suite runs it read-only on each PR, its check-package job, since
// the image is released together with romaine-auth).
if (process.argv.includes("--self-test")) await import("./self-test.js");
else await import("./server.js");
