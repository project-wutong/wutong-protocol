# SPDX-License-Identifier: AGPL-3.0-only
import json, pathlib
base=pathlib.Path(__file__).parent
uuid={'type':'string','pattern':r'^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'}
digest={'type':'string','pattern':r'^sha256:[0-9a-f]{64}$'}
uri={'type':'string','minLength':1,'maxLength':4096}
props={
 'principal': {'principal_id':uuid,'principal_type':{'enum':['human','organization','agent','service','device']},'display_name':{'type':'string','maxLength':256}},
 'space':{'space_id':uuid,'owner_id':uuid,'name':{'type':'string','minLength':1,'maxLength':256},'visibility':{'enum':['local','private','shared','public']}},
 'object':{'object_id':uuid,'space_id':uuid,'object_type':{'type':'string','minLength':1,'maxLength':128},'owner_id':uuid,'title':{'type':'string','maxLength':2048},'content_digest':digest,'media_type':{'type':'string','minLength':1},'byte_length':{'type':'integer','minimum':0},'binding':{'type':'object','additionalProperties':False,'properties':{'kind':{'enum':['file','blob','external']},'relative_path':{'type':'string','minLength':1,'maxLength':4096},'external_uri':uri},'required':['kind']}},
 'revision':{'revision_id':uuid,'object_id':uuid,'content_digest':digest,'parents':{'type':'array','uniqueItems':True,'items':uuid},'author_id':uuid},
 'relation':{'relation_id':uuid,'source_id':uuid,'target_ref':uri,'predicate':{'type':'string','minLength':1,'maxLength':256},'author_id':uuid},
 'proposal':{'proposal_id':uuid,'object_id':uuid,'proposer_id':uuid,'base_digest':digest,'proposed_digest':digest,'intent':{'enum':['replace','patch','metadata','relation']},'status':{'enum':['pending','accepted','rejected','applied','stale']}},
 'task':{'task_id':uuid,'requester_id':uuid,'assignee_id':uuid,'target_ref':uri,'state':{'enum':['created','assigned','accepted','running','awaiting_approval','completed','failed','cancelled']},'artifacts':{'type':'array','items':uri}},
 'capability':{'capability_id':uuid,'issuer_id':uuid,'audience_id':uuid,'resource_ref':uri,'actions':{'type':'array','minItems':1,'uniqueItems':True,'items':{'type':'string','minLength':1}},'not_before':{'type':'string','format':'date-time'},'expires_at':{'type':'string','format':'date-time'},'delegable':{'type':'boolean'},'parent_id':uuid},
 'event':{'event_id':uuid,'actor_id':uuid,'action':{'type':'string','minLength':1},'subject_ref':uri,'result':{'enum':['accepted','rejected','pending','completed','failed']},'causes':{'type':'array','uniqueItems':True,'items':uuid}}
}
required={'principal':['principal_id','principal_type'], 'space':['space_id','owner_id','name','visibility'], 'object':['object_id','space_id','object_type','owner_id','content_digest','media_type','byte_length'], 'revision':['revision_id','object_id','content_digest','parents','author_id'], 'relation':['relation_id','source_id','target_ref','predicate','author_id'], 'proposal':['proposal_id','object_id','proposer_id','base_digest','proposed_digest','intent','status'], 'task':['task_id','requester_id','state'], 'capability':['capability_id','issuer_id','audience_id','resource_ref','actions','expires_at','delegable'], 'event':['event_id','actor_id','action','subject_ref','result']}
proof={'type':'object','additionalProperties':False,'properties':{'alg':{'const':'Ed25519'},'key_id':uri,'sig':{'type':'string','pattern':'^[A-Za-z0-9_-]+$'}},'required':['alg','key_id','sig']}
variants=[]
for name in props:
    v={'type':'object','additionalProperties':False,'properties':{'protocol':{'const':'wutong/0.1'},'kind':{'const':f'wutong.{name}'},'id':uuid,'occurred_at':{'type':'string','format':'date-time'},'payload':{'type':'object','additionalProperties':False,'properties':props[name],'required':required[name]},'proof':proof,'extensions':{'type':'object','propertyNames':{'pattern':'^[a-z0-9]+(\\.[a-z0-9-]+)+$'},'additionalProperties':True}},'required':['protocol','kind','id','occurred_at','payload']}
    variants.append(v)
schema={'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'https://example.org/wutong/v0.1/wutong-core.schema.json', 'title':'Wutong Protocol v0.1 Core Exchange - DESIGN DRAFT (schema URL placeholder)','description':'Syntax only; enforce authorization, file path safety, signatures and identity bindings separately.', 'oneOf':variants}
(base/'schemas'/'wutong-core.schema.json').write_text(json.dumps(schema,ensure_ascii=False,indent=2)+'\n')
U=lambda n:f'urn:uuid:019a1111-1111-7111-8111-{n:012x}'
D='sha256:'+'a'*64
M={'principal':{'principal_id':U(1),'principal_type':'agent','display_name':'Research Agent'}, 'space':{'space_id':U(2),'owner_id':U(3),'name':'Research Workspace','visibility':'local'},'object':{'object_id':U(4),'space_id':U(2),'owner_id':U(3),'object_type':'document','title':'Wutong Protocol Notes','media_type':'text/markdown','byte_length':123,'content_digest':D,'binding':{'kind':'file','relative_path':'notes/wutong.md'}},'revision':{'revision_id':U(5),'object_id':U(4),'content_digest':D,'parents':[],'author_id':U(3)},'relation':{'relation_id':U(6),'source_id':U(4),'target_ref':'https://example.org/paper','predicate':'references','author_id':U(1)},'proposal':{'proposal_id':U(7),'object_id':U(4),'proposer_id':U(1),'base_digest':D,'proposed_digest':'sha256:'+'b'*64,'intent':'replace','status':'pending'},'task':{'task_id':U(8),'requester_id':U(3),'assignee_id':U(1),'target_ref':U(4),'state':'awaiting_approval','artifacts':[U(7)]},'capability':{'capability_id':U(9),'issuer_id':U(3),'audience_id':U(1),'resource_ref':U(4),'actions':['document.propose'],'expires_at':'2026-12-31T00:00:00Z','delegable':False},'event':{'event_id':U(10),'actor_id':U(1),'action':'document.propose','subject_ref':U(4),'result':'pending','causes':[]}}
for name,payload in M.items():
    msg={'protocol':'wutong/0.1','kind':f'wutong.{name}','id':U(100+list(M).index(name)),'occurred_at':'2026-10-18T12:00:00Z','payload':payload}
    (base/'examples'/f'{name}.json').write_text(json.dumps(msg,ensure_ascii=False,indent=2)+'\n')
print('Generated 1 schema with',len(M),'message variants and',len(M),'examples')
