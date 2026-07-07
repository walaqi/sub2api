import landing from './landing'
import common from './common'
import dashboard from './dashboard'
import admin from './admin'
import misc from './misc'

export default {
  batchImageGuide: {
    title: '图片批量生成',
    description: '一次提交多条提示词，任务完成后可统一下载图片结果',
  },
  ...landing,
  ...common,
  ...dashboard,
  admin,
  ...misc,
}
