// The image's entrypoint: the server, or with --self-test the image checking itself
// (pipeline-templates' cluster image check runs it read-only).
if (process.argv.includes("--self-test")) await import("./self-test.js");
else await import("./server.js");
