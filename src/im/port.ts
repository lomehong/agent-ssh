/**
 * 飞书 SDK 适配层（T-17.6，D13 官方 SDK）。
 *
 * LarkPort 把 bot.ts 与 @larksuiteoapi/node-sdk 隔开：单测注入 fake，
 * 真适配只做三件事——WS 长连接（纯出站，NAT 免疫）、发卡片、改卡片。
 * 卡片回调事件名 card.action.trigger；普通消息事件用于捕获发信人
 * open_id（主人给 bot 发第一条消息 → 日志打出，便于填 allowedUsers）。
 */
import * as lark from '@larksuiteoapi/node-sdk';

/** 卡片动作回调（字段按 SDK 事件形态取宽，缺省即拒——绑定校验兜底）。 */
export interface CardActionEvent {
  operatorOpenId?: string;
  /** 按钮 value（含决策令牌）+ form 提交的输入值（challenge）。 */
  value?: Record<string, unknown>;
}

export interface MessageReceiveEvent {
  senderOpenId?: string;
  chatId?: string;
  text?: string;
}

export interface LarkPort {
  /** 建立长连接并注册回调；连接失败 reject（bot 侧降级，不拖垮 Host）。 */
  start(onCardAction: (ev: CardActionEvent) => void, onMessage?: (ev: MessageReceiveEvent) => void): Promise<void>;
  /** 发交互卡片，返回 message_id。 */
  sendCard(receiveIdType: 'open_id' | 'chat_id', receiveId: string, card: Record<string, unknown>): Promise<string>;
  /** 编辑已发卡片（settled 态，D11）。 */
  patchCard(messageId: string, card: Record<string, unknown>): Promise<void>;
}

/** 真适配：SDK Client（消息面）+ WSClient（事件面，长连接纯出站）。 */
export class SdkLarkPort implements LarkPort {
  private readonly client: lark.Client;

  constructor(private readonly appId: string, private readonly appSecret: string) {
    this.client = new lark.Client({ appId, appSecret, domain: lark.Domain.Feishu });
  }

  async start(
    onCardAction: (ev: CardActionEvent) => void,
    onMessage?: (ev: MessageReceiveEvent) => void,
  ): Promise<void> {
    const dispatcher = new lark.EventDispatcher({});
    // 卡片按钮/表单提交。operator.open_id 是绑定校验对象；value 携决策令牌
    // 与（破坏性类）输入的校验码。
    dispatcher.register({
      'card.action.trigger': (data: unknown) => {
        const d = data as {
          operator?: { open_id?: string };
          action?: { value?: Record<string, unknown> };
        };
        onCardAction({ operatorOpenId: d?.operator?.open_id, value: d?.action?.value });
      },
    });
    if (onMessage !== undefined) {
      dispatcher.register({
        'im.message.receive_v1': (data: unknown) => {
          const d = data as {
            sender?: { sender_id?: { open_id?: string } };
            message?: { chat_id?: string };
          };
          onMessage({
            senderOpenId: d?.sender?.sender_id?.open_id,
            chatId: d?.message?.chat_id,
          });
        },
      });
    }
    const ws = new lark.WSClient({ appId: this.appId, appSecret: this.appSecret, loggerLevel: lark.LoggerLevel.warn });
    await ws.start({ eventDispatcher: dispatcher });
  }

  async sendCard(receiveIdType: 'open_id' | 'chat_id', receiveId: string, card: Record<string, unknown>): Promise<string> {
    const res = await this.client.im.v1.message.create({
      params: { receive_id_type: receiveIdType },
      data: {
        receive_id: receiveId,
        msg_type: 'interactive',
        content: JSON.stringify(card),
      },
    });
    if (!res?.data?.message_id) throw new Error('lark sendCard: no message_id in response');
    return res.data.message_id;
  }

  async patchCard(messageId: string, card: Record<string, unknown>): Promise<void> {
    await this.client.im.v1.message.patch({
      path: { message_id: messageId },
      data: { content: JSON.stringify(card) },
    });
  }
}
