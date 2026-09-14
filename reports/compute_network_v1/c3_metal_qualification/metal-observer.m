// Qualification-only runtime observer. Does not modify RISC Zero source or results.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>
#include <stdatomic.h>
static IMP originalCommit, originalSetPipeline;
static atomic_ulong commits, pipelineSets;
static NSMutableSet *labels;
static void observeCommit(id<MTLCommandBuffer> buffer, SEL cmd) {
 unsigned long number=atomic_fetch_add(&commits,1)+1;
 unsigned long pipelineCount=atomic_load(&pipelineSets);
 [buffer addCompletedHandler:^(id<MTLCommandBuffer> done) {
  fprintf(stderr,"AURA_METAL_COMPLETED command=%lu status=%lu gpu_start=%.9f gpu_end=%.9f pipeline_sets=%lu\n",number,(unsigned long)done.status,done.GPUStartTime,done.GPUEndTime,pipelineCount);
 }];
 ((void(*)(id,SEL))originalCommit)(buffer,cmd);
}
static void observePipeline(id encoder, SEL cmd, id<MTLComputePipelineState> pipeline) {
 atomic_fetch_add(&pipelineSets,1);
 NSString *label=pipeline.label ?: @"<unlabelled>";
 @synchronized(labels) {
  if (![labels containsObject:label]) {
   [labels addObject:label];
   fprintf(stderr,"AURA_METAL_PIPELINE label=%s\n",label.UTF8String);
  }
 }
 ((void(*)(id,SEL,id))originalSetPipeline)(encoder,cmd,pipeline);
}
static IMP install(Class cls, SEL sel, IMP hook) {
 Method method=class_getInstanceMethod(cls,sel);
 if (!method) abort();
 IMP previous=method_getImplementation(method);
 if (!class_addMethod(cls,sel,hook,method_getTypeEncoding(method))) class_replaceMethod(cls,sel,hook,method_getTypeEncoding(method));
 return previous;
}
__attribute__((constructor)) static void observerStart(void) {
 @autoreleasepool {
  id<MTLDevice> device=MTLCreateSystemDefaultDevice();
  if (!device) {fprintf(stderr,"AURA_METAL_OBSERVER no_device\n");abort();}
  id<MTLCommandQueue> queue=[device newCommandQueue];
  id<MTLCommandBuffer> buffer=[queue commandBuffer];
  id<MTLComputeCommandEncoder> encoder=[buffer computeCommandEncoder];
  labels=[NSMutableSet new];
  originalCommit=install(object_getClass(buffer),@selector(commit),(IMP)observeCommit);
  originalSetPipeline=install(object_getClass(encoder),@selector(setComputePipelineState:),(IMP)observePipeline);
  [encoder endEncoding];
  fprintf(stderr,"AURA_METAL_OBSERVER device=%s command_class=%s encoder_class=%s\n",device.name.UTF8String,class_getName(object_getClass(buffer)),class_getName(object_getClass(encoder)));
  // This observer never commits its setup buffer and never runs a kernel itself.
 }
}
