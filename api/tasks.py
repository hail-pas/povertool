from povertool.celery import app


@app.task(bind=True, name='定时任务')
def timing_withdraw(self):
    print("定时任务")
    return "定时任务完成"